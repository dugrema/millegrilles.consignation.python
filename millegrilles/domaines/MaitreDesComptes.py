import logging
import datetime
import pytz
import multibase
import json

from pymongo import ReturnDocument
from cryptography.x509.extensions import ExtensionNotFound

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMaitreDesComptes, ConstantesGenerateurCertificat
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementCommandesProtegees, \
    TraitementMessageDomaineRequete, TraitementMessageDomaineCommande
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.util.Webauthn import Webauthn
from millegrilles.util.Hachage import hacher_to_digest
from millegrilles.SecuritePKI import UtilCertificats


class TraitementRequetesPrivees(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if action == ConstantesMaitreDesComptes.REQUETE_CHARGER_USAGER:
            reponse = self.gestionnaire.charger_usager(message_dict)
        elif action == ConstantesMaitreDesComptes.REQUETE_INFO_PROPRIETAIRE:
            reponse = self.gestionnaire.get_info_proprietaire()
        elif action == ConstantesMaitreDesComptes.REQUETE_LISTE_USAGERS:
            reponse = self.gestionnaire.get_liste_usagers(message_dict)
        else:
            return super().traiter_requete(ch, method, properties, body, message_dict, enveloppe_certificat)

        # Genere message reponse
        if reponse:
            correlation_id = properties.correlation_id
            reply_to = properties.reply_to
            self.transmettre_reponse(message_dict, reponse, replying_to=reply_to, correlation_id=correlation_id)

        return reponse


class TraitementRequetesProtegeesMaitreComptes(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if action == ConstantesMaitreDesComptes.REQUETE_CHARGER_USAGER:
            reponse = self.gestionnaire.charger_usager(message_dict)
        elif action == ConstantesMaitreDesComptes.REQUETE_INFO_PROPRIETAIRE:
            reponse = self.gestionnaire.get_info_proprietaire()
        elif action == ConstantesMaitreDesComptes.REQUETE_LISTE_USAGERS:
            reponse = self.gestionnaire.get_liste_usagers(message_dict)
        else:
            return super().traiter_requete(ch, method, properties, body, message_dict, enveloppe_certificat)

        # Genere message reponse
        if reponse:
            correlation_id = properties.correlation_id
            reply_to = properties.reply_to
            self.transmettre_reponse(message_dict, reponse, replying_to=reply_to, correlation_id=correlation_id)

        return reponse


class TraitementCommandesMaitredesclesPrivees(TraitementMessageDomaineCommande):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        resultat: dict
        # if action == ConstantesMaitreDesComptes.COMMANDE_ACTIVATION_TIERCE:
        #     resultat = self.gestionnaire.set_activation_tierce(message_dict)
        if action == ConstantesMaitreDesComptes.COMMANDE_CHALLENGE_COMPTEUSAGER:
            resultat = self.gestionnaire.preparer_challenge_authentification(message_dict)
        elif action == ConstantesMaitreDesComptes.COMMANDE_SIGNER_COMPTEUSAGER:
            resultat = self.gestionnaire.signer_compte_usager(message_dict, properties, enveloppe_certificat)
        else:
            resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class TraitementCommandesMaitredesclesProtegees(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        resultat: dict
        if action == ConstantesMaitreDesComptes.COMMANDE_ACTIVATION_TIERCE:
            resultat = self.gestionnaire.set_activation_tierce(message_dict)
        elif action == ConstantesMaitreDesComptes.COMMANDE_SIGNER_COMPTEUSAGER:
            resultat = self.gestionnaire.signer_compte_usager(message_dict, properties, enveloppe_certificat)
        # if routing_key == 'commande.%s.%s' % (ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.COMMANDE_SIGNER_CLE_BACKUP):
        #     resultat = self.gestionnaire.AAAA()
        # else:
        #     resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)
        else:
            resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class GestionnaireMaitreDesComptes(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self.__handler_requetes = {
            Constantes.SECURITE_SECURE: TraitementRequetesProtegeesMaitreComptes(self),
            Constantes.SECURITE_PRIVE: TraitementRequetesPrivees(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesMaitreComptes(self),
        }

        self.__handler_commandes = {
            Constantes.SECURITE_SECURE: TraitementCommandesMaitredesclesProtegees(self),
            Constantes.SECURITE_PRIVE: TraitementCommandesMaitredesclesPrivees(self),
            Constantes.SECURITE_PROTEGE: TraitementCommandesMaitredesclesProtegees(self),
        }

    def configurer(self):
        super().configurer()

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection_usagers())

        # Index noeud, _mg-libelle
        collection_domaine.create_index(
            [
                (ConstantesMaitreDesComptes.CHAMP_ID_USAGER, 1)
            ],
            name='idusager_unique',
            unique=True,
        )

        collection_domaine.create_index(
            [
                (ConstantesMaitreDesComptes.CHAMP_NOM_USAGER, 1)
            ],
            name='nomusager_unique',
            unique=True,
        )

    def demarrer(self):
        super().demarrer()
        # self.initialiser_document(ConstantesMaitreDesCles.LIBVAL_CONFIGURATION, ConstantesMaitreDesCles.DOCUMENT_DEFAUT)

    def identifier_processus(self, domaine_transaction):

        action = domaine_transaction.split('.')[-1]

        if action == ConstantesMaitreDesComptes.TRANSACTION_INSCRIRE_PROPRIETAIRE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusInscrireProprietaire"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_INSCRIRE_USAGER:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusInscrireUsager"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_AJOUTER_CLE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusAjouterCle"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_SUPPRIMER_CLES:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusSupprimerCles"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_MAJ_MOTDEPASSE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusMajMotdepasse"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_SUPPRESSION_MOTDEPASSE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusSupprimerMotdepasse"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_SUPPRIMER_USAGER:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusSupprimerUsager"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_ASSOCIER_CERTIFICAT:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusAssocierCertificat"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_MAJ_CLEUSAGERPRIVE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusMajCleUsagerPrive"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_AJOUTER_NAVIGATEUR:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusAjouterCertificatNavigateur"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_MAJ_USAGER_TOTP:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusMajUsagerTotp"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_MAJ_USAGER_DELEGATIONS:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusMajDelegationsCompteUsager"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_AJOUTER_DELEGATION_SIGNEE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusAjouterDelegationSignee"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes

    def get_handler_commandes(self) -> dict:
        return self.__handler_commandes

    def get_nom_collection(self):
        return ConstantesMaitreDesComptes.COLLECTION_DOCUMENTS_NOM

    def get_nom_collection_usagers(self):
        return ConstantesMaitreDesComptes.COLLECTION_USAGERS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesMaitreDesComptes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesMaitreDesComptes.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesMaitreDesComptes.DOMAINE_NOM

    def get_nom_queue(self):
        return ConstantesMaitreDesComptes.QUEUE_NOM

    def charger_usager(self, message_dict):
        nom_usager = message_dict.get(ConstantesMaitreDesComptes.CHAMP_NOM_USAGER)
        user_id = message_dict.get(ConstantesMaitreDesComptes.CHAMP_USER_ID)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {
                '$in': [ConstantesMaitreDesComptes.LIBVAL_USAGER, ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE]
            },
        }
        if user_id is not None:
            filtre[ConstantesMaitreDesComptes.CHAMP_USER_ID] = user_id
        elif nom_usager is not None:
            filtre[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER] = nom_usager

        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
        document_usager = collection.find_one(filtre)

        if document_usager:
            champs_conserver = [
                Constantes.DOCUMENT_INFODOC_LIBELLE,
                ConstantesMaitreDesComptes.CHAMP_WEBAUTHN,
                ConstantesMaitreDesComptes.CHAMP_MOTDEPASSE,
                ConstantesMaitreDesComptes.CHAMP_NOM_USAGER,
                ConstantesMaitreDesComptes.CHAMP_TOTP,
                ConstantesMaitreDesComptes.CHAMP_USER_ID,
                ConstantesMaitreDesComptes.CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK,
                ConstantesMaitreDesComptes.CHAMP_COMPTE_PRIVE,
                ConstantesMaitreDesComptes.CHAMP_DELEGATION_GLOBALE,
                ConstantesMaitreDesComptes.CHAMP_DELEGATIONS_DOMAINES,
                ConstantesMaitreDesComptes.CHAMP_DELEGATIONS_SOUSDOMAINES,
                ConstantesMaitreDesComptes.CHAMP_DELEGATIONS_DATE,
            ]
            document_filtre = dict()
            for key, value in document_usager.items():
                if key in champs_conserver:
                    document_filtre[key] = value

            if document_filtre[Constantes.DOCUMENT_INFODOC_LIBELLE] == ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE:
                document_filtre[ConstantesMaitreDesComptes.CHAMP_EST_PROPRIETAIRE] = True

            return document_filtre
        else:
            return {Constantes.EVENEMENT_REPONSE: False}

    def get_info_proprietaire(self):
        """
        Retourne l'information du proprietaire, si existant.
        :return:
        """
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE,
        }
        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
        document_proprietaire = collection.find_one(filtre)
        if document_proprietaire:
            document_proprietaire = self.filtrer_champs_document(document_proprietaire)
        else:
            return {Constantes.EVENEMENT_REPONSE: False}

        return document_proprietaire

    def get_liste_usagers(self, params):
        """
        Liste usagers
        :return:
        """
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {
                '$in': [ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE, ConstantesMaitreDesComptes.LIBVAL_USAGER]
            },
        }
        liste_userids = params.get(ConstantesMaitreDesComptes.CHAMP_LIST_USERIDS)
        if liste_userids:
            filtre[ConstantesMaitreDesComptes.CHAMP_USER_ID] = {'$in': liste_userids}
        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
        curseur = collection.find(filtre)

        batch_usagers = list()
        for usager in curseur:
            user_id = usager[ConstantesMaitreDesComptes.CHAMP_USER_ID]
            nom_usager = usager[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
            compte_prive = usager.get(ConstantesMaitreDesComptes.CHAMP_COMPTE_PRIVE) or False

            batch_usagers.append({
                ConstantesMaitreDesComptes.CHAMP_USER_ID: user_id,
                ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
                ConstantesMaitreDesComptes.CHAMP_COMPTE_PRIVE: compte_prive,
                ConstantesMaitreDesComptes.CHAMP_DELEGATION_GLOBALE: usager.get(ConstantesMaitreDesComptes.CHAMP_DELEGATION_GLOBALE),
            })

        return {'complet': True, 'usagers': batch_usagers}

    def inscrire_proprietaire(self, info_proprietaire: dict):
        date_courante = datetime.datetime.utcnow()

        # cle = info_proprietaire[ConstantesMaitreDesComptes.CHAMP_CLE]

        cle = {
            ConstantesMaitreDesComptes.CHAMP_PK_CRED_ID: info_proprietaire[ConstantesMaitreDesComptes.CHAMP_PK_CRED_ID],
            ConstantesMaitreDesComptes.CHAMP_PK_COUNTER: info_proprietaire[ConstantesMaitreDesComptes.CHAMP_PK_COUNTER],
            ConstantesMaitreDesComptes.CHAMP_PK_PEM: info_proprietaire[ConstantesMaitreDesComptes.CHAMP_PK_PEM],
            ConstantesMaitreDesComptes.CHAMP_PK_TYPE: info_proprietaire[ConstantesMaitreDesComptes.CHAMP_PK_TYPE],
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE,
        }

        doc = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_courante,
            ConstantesMaitreDesComptes.CHAMP_USER_ID: info_proprietaire[ConstantesMaitreDesComptes.CHAMP_USER_ID],
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: info_proprietaire[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER],
            ConstantesMaitreDesComptes.CHAMP_WEBAUTHN: [cle],
        }

        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())

        # S'assurer que le document n'existe pas deja
        doc_existant = collection.find_one(filtre)
        if doc_existant and doc_existant.get(ConstantesMaitreDesComptes.CHAMP_WEBAUTHN):
            raise ValueError("Proprietaire deja assigne pour cette MilleGrille")

        resultat = collection.insert_one(doc)
        if not resultat.inserted_id:
            raise Exception("Erreur prise de possession par le proprietaire, aucun document modifie")

    def inscrire_usager(self, info_usager: dict):
        nom_usager = info_usager[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        id_usager = info_usager[ConstantesMaitreDesComptes.CHAMP_ID_USAGER]
        fingerprint_pk = info_usager[Constantes.ConstantesSecurityPki.LIBELLE_FINGERPRINT_CLE_PUBLIQUE]
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())

        # S'assurer que le compte n'existe pas deja
        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
        filtre_existant = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            '$or': [
                {ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager},
                {ConstantesMaitreDesComptes.CHAMP_USER_ID: id_usager},
            ],
        }
        compte_existant = collection.find_one(filtre_existant)
        if compte_existant is not None:
            return {
                'err': 'Le compte usager existe deja',
                'code': 4,
                'user_id': compte_existant[ConstantesMaitreDesComptes.CHAMP_USER_ID]
            }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }

        set_ops = {
            '.'.join([ConstantesMaitreDesComptes.CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, fingerprint_pk]): {
                'associe': False,
                'date_activation': date_courante
            }
        }

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
            ConstantesMaitreDesComptes.CHAMP_ID_USAGER: id_usager,
        }

        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        resultat = collection.update_one(filtre, ops, upsert=True)
        if not resultat.upserted_id and resultat.matched_count == 0:
            raise Exception("Erreur inscription, aucun document modifie")

    def maj_motdepasse(self, nom_usager: str, motdepasse: dict, est_proprietaire: False):
        set_ops = {
            ConstantesMaitreDesComptes.CHAMP_MOTDEPASSE: motdepasse
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesMaitreDesComptes.LIBVAL_USAGER,
                ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE,
            ]},
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }

        ops = {
            '$set': set_ops,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur maj mot de passe, aucun document modifie")

    def maj_usager_totp(self, transaction: dict):
        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())

        info_totp = transaction['totp']

        filtre = {
            'nomUsager': transaction['nomUsager'],
        }
        set_ops = {
            'totp': info_totp
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        ops = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
        }
        resultat = collection.update_one(filtre, ops, upsert=True)

        if resultat.matched_count != 1 and resultat.inserted_id is None:
            raise Exception("Erreur maj_usager_totp, aucun document modifie")

    def maj_cle_usagerprive(self, nom_usager: str, cle: str):
        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())

        info_usager = collection.find_one({
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        })

        idmg_compte = info_usager[ConstantesMaitreDesComptes.CHAMP_IDMG_COMPTE]

        set_ops = {
            'idmgs.%s.cleChiffreeCompte' % idmg_compte: cle
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }
        ops = {
            '$set': set_ops,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur maj mot de passe, aucun document modifie")

    def suppression_motdepasse(self, nom_usager: str):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {
                '$in': [ConstantesMaitreDesComptes.LIBVAL_USAGER, ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE]
            },
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }
        ops = {
            '$unset': {ConstantesMaitreDesComptes.CHAMP_MOTDEPASSE: True},
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur suppression mot de passe, aucun document modifie")

        return {Constantes.EVENEMENT_REPONSE: True}

    def ajouter_cle(self, cle: dict, nom_usager: str = None, reset_autres_cles=False, fingerprint_pk=None):
        set_ops = {}
        push_ops = {}

        if fingerprint_pk is not None:
            champ_fp = '.'.join(
                [ConstantesMaitreDesComptes.CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, fingerprint_pk, 'associe'])
            champ_date = '.'.join(
                [ConstantesMaitreDesComptes.CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, fingerprint_pk, 'date_association'])
            set_ops[champ_fp] = True
            set_ops[champ_date] = pytz.utc.localize(datetime.datetime.utcnow())

        if reset_autres_cles:
            set_ops[ConstantesMaitreDesComptes.CHAMP_WEBAUTHN] = [cle]
        else:
            push_ops[ConstantesMaitreDesComptes.CHAMP_WEBAUTHN] = cle

        ops = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        if len(set_ops) > 0:
            ops['$set'] = set_ops
        if len(push_ops) > 0:
            ops['$push'] = push_ops

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {
                '$in': [ConstantesMaitreDesComptes.LIBVAL_USAGER, ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE]
            },
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }

        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur ajout cle, aucun document modifie")

    def suppression_cles(self, nom_usager: str = None, user_id: str = None):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
        }
        if nom_usager is not None:
            filtre[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER] = nom_usager
        elif user_id is not None:
            filtre[ConstantesMaitreDesComptes.CHAMP_USER_ID] = user_id
        else:
            return {'err': 'Il faut fournir le user_id ou nom_usager'}

        ops = {
            '$unset': {ConstantesMaitreDesComptes.CHAMP_WEBAUTHN: True},
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur suppression mot de passe, aucun document modifie")

        return {Constantes.EVENEMENT_REPONSE: True}

    def supprimer_usager(self, nom_usager: str):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }
        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
        resultat = collection.delete_one(filtre)
        if resultat.deleted_count != 1:
            raise Exception("Erreur suppression usager, aucun document modifie")

        return {Constantes.EVENEMENT_REPONSE: True}

    def set_activation_tierce(self, commande: dict):
        """
        Ajoute un flag pour indiquer qu'un certificat doit permettre l'enregistrement d'un (1) appareil
        :param commande:
        :return:
        """
        fingerprint_pk = commande[Constantes.ConstantesSecurityPki.LIBELLE_FINGERPRINT_CLE_PUBLIQUE]
        nom_usager = commande[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]

        ts_courant = pytz.utc.localize(datetime.datetime.utcnow())

        set_ops = {
            '.'.join([ConstantesMaitreDesComptes.CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK, fingerprint_pk]): {'associe': False, 'date_activation': ts_courant}
        }
        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        filtre = {
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager
        }

        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur set flag d'activation tierce sur usager %s pour fingerprint %s, "
                            "aucun document modifie" % (nom_usager, fingerprint_pk))

        # Emettre evenement pour indiquer que le certificat est pret
        evenement_activation = {'fingerprint_pk': fingerprint_pk}
        domaine_action = 'evenement.MaitreDesComptes.' + ConstantesMaitreDesComptes.EVENEMENT_ACTIVATION_FINGERPRINTPK
        self.generateur_transactions.emettre_message(
            evenement_activation,
            domaine_action,
            exchanges=[Constantes.SECURITE_PRIVE, Constantes.SECURITE_PROTEGE]
        )

        return {'ok': True}

    def signer_compte_usager(self, params: dict, properties, enveloppe_certificat):
        """
        Debut du processus de signature d'un certificat de navigateur pour un usager.

        :param params:
        :param properties:
        :param enveloppe_certificat:
        :return:
        """
        # Verifier que l'enveloppe de certificat provient d'un serveur prive (monitor) ou protege (web_protege)
        roles = enveloppe_certificat.get_roles
        exchanges = enveloppe_certificat.get_exchanges
        activation_tierce = False

        if Constantes.SECURITE_PRIVE not in exchanges and Constantes.SECURITE_PROTEGE not in exchanges:
            return {'err': 'Permission refusee', 'code': 1}

        if ConstantesGenerateurCertificat.ROLE_MAITRE_COMPTES not in roles:
            return {'err': 'Permission refusee', 'code': 2}

        # Charger l'usager de la base de donnees
        # Sanity check - user_id fourni par le serveur web et nom_usager fourni par le navigateur doivent correspondre
        # au meme compte dans la base de donnees.
        # NOTE : on devrait aussi charger le CSR et verifier que CN=nom_usager

        collection = self.document_dao.get_collection(ConstantesMaitreDesComptes.COLLECTION_USAGERS_NOM)
        user_id = params['userId']
        filtre = {
            ConstantesMaitreDesComptes.CHAMP_USER_ID: user_id,
        }
        doc_usager = collection.find_one(filtre)

        if doc_usager is None:
            return {'ok': False, 'err': 'Permission refusee', 'code': 3}

        try:
            demande_certificat = params['demandeCertificat']
        except KeyError:
            # On n'a pas de demande. Verifier les cas d'exception.
            # Cas 1 - nouvel usager, le compte n'aura aucun token webauthn
            permission = params.get('permission')
            demande_certificat = {
                'nomUsager': doc_usager['nomUsager'],
                'csr': params['csr'],
            }

            if permission is not None:
                # On a une permission signee - s'assurer que c'est un certificat 4.secure ou avec delegation
                enveloppe_permission = self.validateur_message.verifier(permission)
                activation_tierce = permission.get('activationTierce')
                try:
                    exchanges = enveloppe_permission.get_exchanges
                except ExtensionNotFound:
                    exchanges = None
                try:
                    delegation_globale = enveloppe_permission.get_delegation_globale
                except ExtensionNotFound:
                    delegation_globale = None

                if delegation_globale not in ['proprietaire'] and Constantes.SECURITE_SECURE not in exchanges:
                    return {'ok': False, 'err': "La signature de la permission n'est pas faite avec un niveau d'acces approprie"}

                try:
                    demande_certificat['activationTierce'] = permission['activationTierce']
                except KeyError:
                    pass  # OK

            elif doc_usager.get('webauthn') is not None:
                return {'ok': False, 'err': 'Absence de signature webauthn pour creer certificat sur compte existant', 'code': 5}

        else:
            nom_usager = demande_certificat['nomUsager']
            if doc_usager['nomUsager'] != nom_usager:
                return {'ok': True, 'err': 'Mismatch nom usager dans le compte', 'code': 4}

            # Valider signature du message demandeCertificat avec webauthn
            date_demande = demande_certificat['date']
            date_demande = datetime.datetime.fromtimestamp(date_demande)

            # S'assurer que la demande n'est pas trop vieille (fenetre de +/- 15 minutes)
            expiration = datetime.timedelta(minutes=15)
            date_now = datetime.datetime.utcnow()
            if not date_now <= date_demande + expiration and date_now > date_demande - expiration:
                return {'ok': False, 'err': 'Demande expiree'}

            challenge_serveur = params['challenge']
            challenge_bytes: bytes = multibase.decode(challenge_serveur)
            if challenge_bytes[0] != 0x2:
                return {'ok': False, 'err': 'Le challenge de demande de certificat doit commencer par 0x2'}

            # Calculer SHA512 de la demande, remplacer bytes [1:65] du challenge
            # Preparer le message pour verification du hachage et de la signature
            message_bytes = UtilCertificats.preparer_message_bytes(demande_certificat)
            digest = hacher_to_digest(message_bytes, hashing_code='sha2-512')

            # S'assurer que le digest correspond au bytes [1:65] du challenge
            if digest != challenge_bytes[1:65]:
                return {'ok': False, 'err': 'Le digest de la demande de signature de CSR dans le challenge est incorrect'}

            auth_response = params['clientAssertionResponse']
            origin = params['origin']
            url_site = origin.replace('https://', '')
            webauthn_verif = Webauthn(self.configuration.idmg)

            assertions = {
                'challenge': challenge_serveur,
                'rpId': url_site,
            }
            webauthn_verif.authenticate_complete(url_site, assertions, auth_response, doc_usager['webauthn'])

        # Cleanup
        try:
            del doc_usager[ConstantesMaitreDesComptes.CHAMP_WEBAUTHN]
        except KeyError:
            pass  # OK
        try:
            del doc_usager[ConstantesMaitreDesComptes.CHAMP_ACTIVATIONS_PAR_FINGERPRINT_PK]
        except KeyError:
            pass  # OK
        for key in doc_usager.copy().keys():
            if key.startswith('_'):
                del doc_usager[key]

        # Creer l'information pour la commande de signature de certificat
        commande_signature = demande_certificat.copy()
        commande_signature['userId'] = params['userId']
        commande_signature['compte'] = doc_usager

        # Ajouter flag tiers si active d'un autre appareil que l'origine du CSR
        # Donne le droit a l'usager de faire un login initial et enregistrer son appareil.
        if demande_certificat.get('activationTierce') is True or activation_tierce is True:
            commande_signature['activation_tierce'] = True

        # Emettre le compte usager pour qu'il soit signe et retourne au demandeur (serveur web)
        domaine_action = 'commande.servicemonitor.signerNavigateur'
        self.generateur_transactions.transmettre_commande(
            commande_signature,
            domaine_action,
            exchange=Constantes.SECURITE_PROTEGE,
            reply_to=properties.reply_to,
            correlation_id=properties.correlation_id,
            ajouter_certificats=True,
        )

    def maj_delegations(self, user_id, params: dict):
        set_ops = dict()
        champs = [
            ConstantesMaitreDesComptes.CHAMP_COMPTE_PRIVE,
            ConstantesMaitreDesComptes.CHAMP_DELEGATION_GLOBALE,
            ConstantesMaitreDesComptes.CHAMP_DELEGATIONS_DOMAINES,
            ConstantesMaitreDesComptes.CHAMP_DELEGATIONS_SOUSDOMAINES,
        ]
        for champ in champs:
            try:
                set_ops[champ] = params[champ]
            except KeyError:
                pass  # OK

        set_ops[ConstantesMaitreDesComptes.CHAMP_DELEGATIONS_DATE] = datetime.datetime.utcnow()

        ops = {
            '$set': set_ops,
        }

        filtre = {ConstantesMaitreDesComptes.CHAMP_USER_ID: user_id}
        collection = self.document_dao.get_collection(ConstantesMaitreDesComptes.COLLECTION_USAGERS_NOM)
        resultat = collection.find_one_and_update(filtre, ops, return_document=ReturnDocument.AFTER)

        return resultat

    def ajouter_delegation_globale_signee(self, user_id: str, confirmation: dict):
        """
        Permet d'ajouter une delegation globale via signature par cle de millegrille
        :param user_id:
        :param confirmation:
        :return:
        """

        enveloppe_millegrille = self._contexte.signateur_transactions.get_enveloppe_millegrille()

        try:
            self.validateur_message.verifier_signature_message(confirmation, enveloppe_millegrille)
        except Exception as e:
            # Exception, signifie que la signature est invalide
            self._logger.exception("Erreur verification signature de millegrille")
            return False

        # La confirmation est bien signee par la cle de millegrille. On peut proceder.
        self.maj_delegations(
            user_id,
            {ConstantesMaitreDesComptes.CHAMP_DELEGATION_GLOBALE: ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE}
        )
        return True

    def preparer_challenge_authentification(self, params: dict):
        nom_usager = params['nom_usager']
        url_site = params['url_site']

        filtre = {'nomUsager': nom_usager}
        collection_usagers = self.document_dao.get_collection(ConstantesMaitreDesComptes.COLLECTION_USAGERS_NOM)
        doc_usager = collection_usagers.find_one(filtre)
        creds = doc_usager[ConstantesMaitreDesComptes.CHAMP_WEBAUTHN]

        # Generer un challenge aleatoire
        wa = Webauthn()
        challenge = wa.generer_challenge_auth(url_site, creds)

        # Conserver challenge dans le compte usager (volatil)
        info_challenge = {
            'date': datetime.datetime.utcnow(),
            'challenge': challenge['challenge'],
            'rpId': challenge['rpId'],
            'userVerification': challenge['userVerification'],
        }
        ops = {
            '$set': {'webauthn_challenge': info_challenge},
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        collection_usagers.update_one(filtre, ops)

        return challenge


class ProcessusInscrireProprietaire(MGProcessusTransaction):
    """
    Permet au proprietaire de prendre possession de sa MilleGrille.
    """
    def initiale(self):
        transaction = self.transaction_filtree
        self.controleur.gestionnaire.inscrire_proprietaire(transaction)
        self.set_etape_suivante()  # Termine


class ProcessusInscrireUsager(MGProcessusTransaction):
    """
    Inscrit un nouvel usager.
    Note : si l'usager existe deja, fait une mise a jour
    """
    def initiale(self):
        transaction = self.transaction_filtree
        self.controleur.gestionnaire.inscrire_usager(transaction)
        self.set_etape_suivante()  #Termine

        return {'ok': True}


class ProcessusMajMotdepasse(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        motdepasse = transaction[ConstantesMaitreDesComptes.CHAMP_MOTDEPASSE]
        est_proprietaire = transaction.get(ConstantesMaitreDesComptes.CHAMP_EST_PROPRIETAIRE) or False
        self.controleur.gestionnaire.maj_motdepasse(nom_usager, motdepasse, est_proprietaire)

        self.set_etape_suivante()  #Termine


class ProcessusMajUsagerTotp(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        self.controleur.gestionnaire.maj_usager_totp(transaction)

        self.set_etape_suivante()  #Termine

        return {'ok': True}


class ProcessusMajCleUsagerPrive(MGProcessusTransaction):
    """
    Met a jour la cle privee de l'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        cle = transaction[ConstantesMaitreDesComptes.CHAMP_CLE]
        self.controleur.gestionnaire.maj_cle_usagerprive(nom_usager, cle)

        self.set_etape_suivante()  #Termine


class ProcessusMajDelegationsCompteUsager(MGProcessusTransaction):
    """
    Met a jour delegations et flag compte_prive
    """
    def initiale(self):
        transaction = self.transaction

        user_id = transaction[ConstantesMaitreDesComptes.CHAMP_USER_ID]
        resultat = self.controleur.gestionnaire.maj_delegations(user_id, transaction)

        self.set_etape_suivante()  #Termine

        return resultat


class ProcessusSupprimerMotdepasse(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        self.controleur.gestionnaire.suppression_motdepasse(nom_usager)

        self.set_etape_suivante()  #Termine


class ProcessusAjouterCle(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction.get(ConstantesMaitreDesComptes.CHAMP_NOM_USAGER)
        cle = self.transaction[ConstantesMaitreDesComptes.CHAMP_CLE]
        fingerprint_pk = self.transaction.get(Constantes.ConstantesSecurityPki.LIBELLE_FINGERPRINT_CLE_PUBLIQUE)
        reset_autres_cles = transaction.get(ConstantesMaitreDesComptes.CHAMP_RESET_CLES) or False
        self.controleur.gestionnaire.ajouter_cle(
            cle, nom_usager=nom_usager, reset_autres_cles=reset_autres_cles,
            fingerprint_pk=fingerprint_pk)

        self.set_etape_suivante()  #Termine


class ProcessusSupprimerCles(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction.get(ConstantesMaitreDesComptes.CHAMP_NOM_USAGER)
        user_id = transaction.get(ConstantesMaitreDesComptes.CHAMP_USER_ID)
        self.controleur.gestionnaire.suppression_cles(nom_usager, user_id)

        self.set_etape_suivante()  #Termine


class ProcessusSupprimerUsager(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        self.controleur.gestionnaire.supprimer_usager(nom_usager)

        self.set_etape_suivante()  #Termine


class ProcessusAssocierCertificat(MGProcessusTransaction):
    """
    Associe un IDMG au compte. Ajoute optionnellement la cle intermediaire et la chaine de certificats.
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        idmg = transaction.get(Constantes.CONFIG_IDMG)
        chaine_certificats = transaction.get(ConstantesMaitreDesComptes.CHAMP_CHAINE_CERTIFICAT)
        cle_intermediaire = transaction.get(ConstantesMaitreDesComptes.CHAMP_CLE)
        reset_certificats = transaction.get(ConstantesMaitreDesComptes.CHAMP_RESET_CERTIFICATS) or False

        self.controleur.gestionnaire.associer_idmg(
            nom_usager, idmg, chaine_certificats=chaine_certificats, cle_intermediaire=cle_intermediaire, reset_certificats=reset_certificats)

        self.set_etape_suivante()  #Termine


class ProcessusAjouterCertificatNavigateur(MGProcessusTransaction):
    """
    Associe un IDMG au compte. Ajoute optionnellement la cle intermediaire et la chaine de certificats.
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]

        self.controleur.gestionnaire.ajouter_certificat_navigateur(nom_usager, transaction)

        self.set_etape_suivante()  #Termine


class ProcessusAjouterDelegationSignee(MGProcessusTransaction):
    """
    Ajoute une delegation globale pour un usager - doit contenir une confirmation signee par la cle de millegrille
    """
    def initiale(self):
        transaction = self.transaction

        user_id = transaction[ConstantesMaitreDesComptes.CHAMP_USER_ID]
        confirmation = transaction[ConstantesMaitreDesComptes.CHAMP_CONFIRMATION]
        resultat = self.controleur.gestionnaire.ajouter_delegation_globale_signee(user_id, confirmation)

        self.set_etape_suivante()  #Termine

        return {'ok': resultat}