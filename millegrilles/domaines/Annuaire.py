from millegrilles import Constantes
from millegrilles.Constantes import ConstantesAnnuaire
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, TraitementRequetesProtegees, ExchangeRouter
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.util.X509Certificate import PemHelpers
from millegrilles.SecuritePKI import EnveloppeCertificat

from pymongo.collection import ReturnDocument

import datetime
import logging


class TraitementRequetesAnnuaire(TraitementRequetesProtegees):

    def _preparerFiche(self, fiche):
        # Filtrer les champs MongoDB et MilleGrilles qui ne sont pas natifs a la fiche
        champs_enlever = [
            '_id',
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION,
            Constantes.DOCUMENT_INFODOC_LIBELLE
        ]
        for champ in champs_enlever:
            del fiche[champ]


class TraitementRequetesPubliquesAnnuaire(TraitementRequetesAnnuaire):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if action == ConstantesAnnuaire.REQUETE_FICHE_PUBLIQUE:
            fiche_publique = self.gestionnaire.get_fiche_publique()
            self.transmettre_reponse(message_dict, fiche_publique, properties.reply_to, properties.correlation_id)
        else:
            raise Exception("Requete publique non supportee " + routing_key)


class TraitementRequetesProtegeesAnnuaire(TraitementRequetesAnnuaire):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        reponse = None
        if action == ConstantesAnnuaire.REQUETE_FICHE_PUBLIQUE:
            reponse = self.gestionnaire.get_fiche_publique()
        elif routing_key == 'requete.' + ConstantesAnnuaire.REQUETE_FICHE_PRIVEE:
            fiche_privee = self.gestionnaire.get_fiche_privee()

            # Filtrer les champs MongoDB et MilleGrilles qui ne sont pas natifs a la fiche
            champs_enlever = [
                '_id',
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION,
                Constantes.DOCUMENT_INFODOC_LIBELLE
            ]
            for champ in champs_enlever:
                del fiche_privee[champ]

            reponse = fiche_privee
        else:
            super().traiter_requete(ch, method, properties, body, message_dict)

        if reponse:
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class GestionnaireAnnuaire(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_requetes = {
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesAnnuaire(self),
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliquesAnnuaire(self),
        }

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def configurer(self):
        super().configurer()

    def demarrer(self):
        super().demarrer()

        # Initialiser fiches privees et publiques au besoin
        fiche_privee = ConstantesAnnuaire.TEMPLATE_DOCUMENT_FICHE_MILLEGRILLE_PRIVEE.copy()
        fiche_privee[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG] = self.configuration.idmg
        fiche_publique = ConstantesAnnuaire.TEMPLATE_DOCUMENT_FICHE_MILLEGRILLE_PUBLIQUE.copy()
        fiche_publique[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG] = self.configuration.idmg
        with open(self.configuration.pki_cafile, 'r') as fichier:
            ca_pem = fichier.read()
            split_certs = PemHelpers.split_certificats(ca_pem)
            if len(split_certs) > 1:
                self.__logger.warning("Plusieurs certificats CA trouves: %s" % ca_pem)
                self.__logger.error("Le fichier de certificat CA (%s) est mauvais, il contient plusieurs certificats" % self.configuration.pki_cafile)
        fiche_privee[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT_RACINE] = ca_pem
        fiche_publique[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT_RACINE] = ca_pem

        self.initialiser_document(ConstantesAnnuaire.LIBVAL_FICHE_PRIVEE, fiche_privee)
        self.initialiser_document(ConstantesAnnuaire.LIBVAL_FICHE_PUBLIQUE, fiche_publique)

        # Initialiser index au besoin
        self.initialiser_document(ConstantesAnnuaire.LIBVAL_INDEX_MILLEGRILLES, ConstantesAnnuaire.TEMPLATE_DOCUMENT_INDEX_MILLEGRILLES.copy())

        self.demarrer_watcher_collection(
            ConstantesAnnuaire.COLLECTION_DOCUMENTS_NOM,
            ConstantesAnnuaire.QUEUE_ROUTING_CHANGEMENTS,
            AnnuaireExchangeRouter(self._contexte)
        )

    def get_nom_queue(self):
        return ConstantesAnnuaire.QUEUE_SUFFIXE

    def get_nom_collection(self):
        return ConstantesAnnuaire.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesAnnuaire.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesAnnuaire.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesAnnuaire.DOMAINE_NOM

    def get_handler_requetes(self) -> dict:
        return self._traitement_requetes

    def traiter_cedule(self, message):
        timestamp_message = message['timestamp']['UTC']
        if timestamp_message[4] % 6 == 0:
            self.__logger.debug("Executer entretien annuaire (6 heures)")
            # Declencher la verification des actions sur taches

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == ConstantesAnnuaire.TRANSACTION_MAJ_FICHEPRIVEE:
            processus = "millegrilles_domaines_Annuaire:ProcessusMajFichePrivee"
        elif domaine_transaction == ConstantesAnnuaire.TRANSACTION_MAJ_FICHEPUBLIQUE:
            processus = "millegrilles_domaines_Annuaire:ProcessusMajFichePublique"
        elif domaine_transaction == ConstantesAnnuaire.TRANSACTION_MAJ_FICHETIERCE:
            processus = "millegrilles_domaines_Annuaire:ProcessusMajFicheTierce"
        elif domaine_transaction == ConstantesAnnuaire.TRANSACTION_DEMANDER_INSCRIPTION:
            processus = "millegrilles_domaines_Annuaire:ProcessusDemanderInscription"
        elif domaine_transaction == ConstantesAnnuaire.TRANSACTION_INSCRIRE_TIERS:
            processus = "millegrilles_domaines_Annuaire:ProcessusInscrireTiersLocalement"
        elif domaine_transaction == ConstantesAnnuaire.TRANSACTION_SIGNATURE_INSCRIPTION_TIERS:
            processus = "millegrilles_domaines_Annuaire:ProcessusSignatureInscriptionTiers"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def maj_fiche_privee(self, fiche):
        return self.__maj_fiche(fiche, ConstantesAnnuaire.LIBVAL_FICHE_PRIVEE)

    def maj_fiche_publique(self, fiche):
        return self.__maj_fiche(fiche, ConstantesAnnuaire.LIBVAL_FICHE_PUBLIQUE)

    def __maj_fiche(self, fiche, type_fiche):
        self.valider_signature_fiche(fiche)

        # Extraire toutes les valeurs de la transaction qui ne commencent pas par un '_'
        set_ops = dict()
        for key, value in fiche.items():
            if not key.startswith('_') and key not in [Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]:
                set_ops[key] = value

        # Ajouter certificat local
        with open(self.configuration.pki_certfile, 'r') as fichier:
            cert_local_fichier = fichier.read()
            cert_local = PemHelpers.split_certificats(cert_local_fichier)[0]
        set_ops[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT_ADDITIONNELS] = [cert_local]

        # Effectuer la mise a jour
        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: type_fiche
        }

        collection_domaine = self.document_dao.get_collection(ConstantesAnnuaire.COLLECTION_DOCUMENTS_NOM)
        fiche_maj = collection_domaine.find_one_and_update(filtre, update=ops, return_document=ReturnDocument.AFTER)

        # Remettre l'entete et la signature pour pouvoir exporter la fiche
        del fiche_maj['_id']  # Enlever le MongoID
        # del fiche_maj[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]  # Enlever Entete, on va en mettre une nouvelle
        # del fiche_maj[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE]  # Enlever _signature

        # Preparer la fiche pour etre exportee (transaction maj.fiche.tierce)
        fiche_exportee = self.generateur_transactions.preparer_enveloppe(fiche_maj, ConstantesAnnuaire.TRANSACTION_MAJ_FICHETIERCE)
        info_recalculee = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE: fiche_exportee[
                Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE],
            Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE: fiche_exportee[
                Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE],
        }

        # Mettre a jour la fiche avec la nouvelle entete et signature
        collection_domaine.update_one(filtre, {'$set': info_recalculee})

        # Mise a jour index
        descriptif = fiche_exportee.get(ConstantesAnnuaire.LIBELLE_DOC_DESCRIPTIF)
        if descriptif is None:
            descriptif = fiche_exportee[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]

        set_index = {
            '%s.%s.%s' % (
                ConstantesAnnuaire.LIBELLE_DOC_LISTE,
                fiche_exportee[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG],
                ConstantesAnnuaire.LIBELLE_DOC_DESCRIPTIF
            ): descriptif,
            '%s.%s.%s' % (
                ConstantesAnnuaire.LIBELLE_DOC_LISTE,
                fiche_exportee[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG],
                ConstantesAnnuaire.LIBELLE_DOC_TYPE_FICHE
            ): type_fiche,
        }
        collection_domaine.update_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesAnnuaire.LIBVAL_INDEX_MILLEGRILLES},
            {'$set': set_index}
        )

        return fiche_exportee

    def valider_signature_fiche(self, fiche):
        """
        Valide la signature de la fiche en utilisant les certificats racine, intermediaire et _certificat_.
        """
        self.__logger.warning("ATTENTION! valider_signature_fiche PAS IMPLEMENTE")
        return True

    def get_fiche_privee(self):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesAnnuaire.LIBVAL_FICHE_PRIVEE
        }

        collection_domaine = self.document_dao.get_collection(ConstantesAnnuaire.COLLECTION_DOCUMENTS_NOM)
        fiche_privee = collection_domaine.find_one(filtre)
        return fiche_privee

    def get_fiche_publique(self):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesAnnuaire.LIBVAL_FICHE_PUBLIQUE
        }

        collection_domaine = self.document_dao.get_collection(ConstantesAnnuaire.COLLECTION_DOCUMENTS_NOM)
        fiche_publique = collection_domaine.find_one(filtre)
        return fiche_publique

    def ajouter_demande_inscription(self, demande_inscription):
        # Determiner si la demande est pour une millegrille tierce si c'est une demande locale vers un tiers
        idmg_sollicite = demande_inscription[ConstantesAnnuaire.LIBELLE_DOC_IDMG_SOLLICITE]
        idmg_originateur = demande_inscription[ConstantesAnnuaire.LIBELLE_DOC_FICHE_PRIVEE][Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]

        if idmg_sollicite == self.configuration.idmg:
            self.__logger.debug("Demande de la MilleGrille %s pour se connecter localement" % idmg_originateur)
            champ_demande = ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_RECUES
            idmg_distant = idmg_originateur
        else:
            self.__logger.debug("Sauvegarder demande d'inscription vers %s" % idmg_sollicite)
            champ_demande = ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_TRANSMISES
            idmg_distant = idmg_sollicite

        # On conserver la demande au complet pour la retransmettre a la MilleGrille tierce
        demande_copy = demande_inscription.copy()

        filtrer_champs_millegrille = [
            '_id',
            Constantes.TRANSACTION_MESSAGE_LIBELLE_ORIGINE,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT
        ]
        for champ in filtrer_champs_millegrille:
            del demande_copy[champ]

        demande_csr = {
            ConstantesAnnuaire.LIBELLE_DOC_DATE_DEMANDE: demande_inscription[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE],
            ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_CORRELATION: demande_inscription[ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_CORRELATION],
            ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_ORIGINALE: demande_copy,
        }

        on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesAnnuaire.LIBVAL_FICHE_TIERS,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG: idmg_distant,
        }

        ops = {
            '$push': {
                champ_demande: demande_csr
            },
            '$setOnInsert': on_insert,
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesAnnuaire.LIBVAL_FICHE_TIERS,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG: idmg_distant,
        }

        collection_domaine = self.document_dao.get_collection(ConstantesAnnuaire.COLLECTION_DOCUMENTS_NOM)
        collection_domaine.update_one(filtre, ops, upsert=True)

    def ajouter_inscription(self, inscription):
        # Determiner si la demande est pour une millegrille tierce si c'est une demande locale vers un tiers
        idmg_sollicite = inscription[ConstantesAnnuaire.LIBELLE_DOC_IDMG_SOLLICITE]
        idmg_originateur = inscription[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]

        set_ops = {}

        if idmg_sollicite == self.configuration.idmg:
            self.__logger.debug("Inscription de la MilleGrille %s pour se connecter localement" % idmg_originateur)
            champ_inscription = ConstantesAnnuaire.LIBELLE_DOC_INSCRIPTIONS_TIERS_VERS_LOCAL
            idmg_distant = idmg_originateur
        else:
            self.__logger.debug("Sauvegarder inscription vers %s" % idmg_sollicite)
            champ_inscription = ConstantesAnnuaire.LIBELLE_DOC_INSCRIPTIONS_LOCAL_VERS_TIERS
            idmg_distant = idmg_sollicite

            # Extraire fiche privee
            fiche_privee = inscription[ConstantesAnnuaire.LIBELLE_DOC_FICHE_PRIVEE]
            set_ops[ConstantesAnnuaire.LIBELLE_DOC_FICHE_PRIVEE] = fiche_privee

            certificat_connecteur = inscription[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT]
            enveloppe_certificat = EnveloppeCertificat(certificat_pem=certificat_connecteur)

            correlation_csr = inscription[ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_CORRELATION]
            # Generer une transaction de certificat pour PKI
            self.generateur_transactions.emettre_certificat(certificat_connecteur, enveloppe_certificat.fingerprint_ascii, correlation_csr)

        # On conserver la demande au complet pour la retransmettre a la MilleGrille tierce
        inscription_copy = inscription.copy()

        filtrer_champs_millegrille = [
            '_id',
            Constantes.TRANSACTION_MESSAGE_LIBELLE_ORIGINE,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT
        ]
        for champ in filtrer_champs_millegrille:
            del inscription_copy[champ]

        demande_csr = {
            ConstantesAnnuaire.LIBELLE_DOC_DATE_DEMANDE: inscription[
                Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE],
            ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_CORRELATION: inscription[
                ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_CORRELATION],
            ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_ORIGINALE: inscription_copy,
        }

        on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesAnnuaire.LIBVAL_FICHE_TIERS,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG: idmg_distant,
        }

        ops = {
            '$push': {
                champ_inscription: demande_csr
            },
            '$setOnInsert': on_insert,
        }
        if len(set_ops.keys()) > 0:
            ops['$set'] = set_ops

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesAnnuaire.LIBVAL_FICHE_TIERS,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG: idmg_distant,
        }

        collection_domaine = self.document_dao.get_collection(ConstantesAnnuaire.COLLECTION_DOCUMENTS_NOM)
        collection_domaine.update_one(filtre, ops, upsert=True)


class AnnuaireExchangeRouter(ExchangeRouter):

    def determiner_exchanges(self, document):
        """
        :return: Liste des echanges sur lesquels le document doit etre soumis
        """
        exchanges = set()
        mg_libelle = document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)
        if mg_libelle in [ConstantesAnnuaire.LIBVAL_FICHE_PUBLIQUE]:
            exchanges.add(self._exchange_public)
            exchanges.add(self._exchange_prive)
            exchanges.add(self._exchange_protege)
        elif mg_libelle in [ConstantesAnnuaire.LIBVAL_FICHE_PRIVEE]:
            exchanges.add(self._exchange_prive)
            exchanges.add(self._exchange_protege)
        else:
            exchanges.add(self._exchange_protege)

        return list(exchanges)


class ProcessusAnnuaire(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesAnnuaire.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesAnnuaire.COLLECTION_PROCESSUS_NOM


class ProcessusMajFichePrivee(ProcessusAnnuaire):
    """
    Met a jour la fiche privee
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction

        fiche_exportee = self.controleur.gestionnaire.maj_fiche_privee(transaction)

        if fiche_exportee.get(ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT) or self.controleur.is_regeneration:
            self.set_etape_suivante()  # Termine
        else:
            # Le certificat du maitre des cles n'a pas ete ajoute. On fait une requete pour resoumettre en transaction.
            domaine = 'millegrilles.domaines.MaitreDesCles.certMaitreDesCles'
            requete = {
                '_evenements': 'certMaitreDesCles'
            }

            self.set_requete(domaine, requete)
            self.set_etape_suivante(ProcessusMajFichePrivee.maj_maitredescles.__name__)

    def maj_maitredescles(self):
        reponse = self.parametres['reponse'][0]

        # self.controleur.gestionnaire.maj_fiche_privee(reponse)

        # Resoumettre cette transaction avec l'information du maitre des cles
        self.ajouter_transaction_a_soumettre(ConstantesAnnuaire.TRANSACTION_MAJ_FICHEPRIVEE, reponse)

        self.set_etape_suivante()  # Termine


class ProcessusMajFichePublique(ProcessusAnnuaire):
    """
    Ajoute/met a jour et publie la fiche publique
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction

        fiche_exportee = self.controleur.gestionnaire.maj_fiche_publique(transaction)

        if fiche_exportee.get(ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT) or self.controleur.is_regeneration:
            self.set_etape_suivante()  # Termine
        else:
            # Le certificat du maitre des cles n'a pas ete ajoute. On fait une requete.
            domaine = 'millegrilles.domaines.MaitreDesCles.certMaitreDesCles'
            requete = {
                '_evenements': 'certMaitreDesCles'
            }

            self.set_requete(domaine, requete)
            self.set_etape_suivante(ProcessusMajFichePublique.maj_maitredescles.__name__)

    def maj_maitredescles(self):
        reponse = self.parametres['reponse'][0]

        # Resoumettre cette transaction avec l'information du maitre des cles
        self.ajouter_transaction_a_soumettre(ConstantesAnnuaire.TRANSACTION_MAJ_FICHEPUBLIQUE, reponse)

        self.set_etape_suivante()  # Termine


class ProcessusMajFicheTierce(ProcessusAnnuaire):
    """
    Ajoute/met a jour une fiche de MilleGrille tierce
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine


class ProcessusInscrireTiersLocalement(ProcessusAnnuaire):
    """
    Processus initial qui mene a generer un certificat de connexion a la MilleGrille locale
    suite a une demande d'une MilleGrille tierce. Genere une notification a l'usager avant de
    repondre a la MilleGrille tierce.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        fiche_privee = transaction[ConstantesAnnuaire.LIBELLE_DOC_FICHE_PRIVEE]

        # Verification et mise a jour de la fiche de millegrille tierce.
        self.controleur.gestionnaire.maj_fiche_privee(fiche_privee)

        self.set_etape_suivante()  # Termine


class ProcessusRefuserInscriptionMilleGrilleTierceLocalement(ProcessusAnnuaire):
    """
    Processus pour refuser l'inscription d'une MilleGrille tierce.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction

        # Verification et mise a jour de la fiche de millegrille tierce.

        self.set_etape_suivante()  # Termine


class ProcessusDemanderInscription(ProcessusAnnuaire):
    """
    Processus de demande de certificat a une MilleGrille tierce.
    Pour savoir si la demande est pour la MilleGrille locale un ou tiers, il faut verifier avec le idmg
    de la requete.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction

        # Mettre la jour la fiche du tiers avec l'information de demande
        self.controleur.gestionnaire.ajouter_demande_inscription(transaction)

        self.set_etape_suivante()  # Termine


class ProcessusSignatureInscriptionTiers(ProcessusAnnuaire):
    """
    Transaction avec le certificat d'inscription signe.
    Cette transaction doit etre sauvegardee par la MilleGrille signataire et appliquee dans le connecteur
    de la MilleGrille inscrite.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.controleur.gestionnaire.ajouter_inscription(transaction)

        self.set_etape_suivante()  # Termine


class ProcessusDemarrerConversation(ProcessusAnnuaire):
    """
    Permet de demarrer une conversation avec une MilleGrille tierce.
    Transmet une cle secrete cryptee avec la cle publique dans la fiche tierce.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine


class ProcessusRecevoirMessageProtege(ProcessusAnnuaire):
    """
    Recoit un message d'une MilleGrille tierce.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine


class ProcessusTransmettreMessageProtege(ProcessusAnnuaire):
    """
    Transmet un message a une MilleGrille tierce.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine

