import logging
import datetime
import pytz

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMaitreDesComptes
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesNoeuds, TraitementRequetesProtegees, TraitementCommandesProtegees, \
    TransactionTypeInconnuError
from millegrilles.MGProcessus import MGProcessusTransaction


class TraitementRequetesProtegeesMaitreComptes(TraitementRequetesProtegees):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if action == ConstantesMaitreDesComptes.REQUETE_CHARGER_USAGER:
            reponse = self.gestionnaire.charger_usager(message_dict)
        elif action == ConstantesMaitreDesComptes.REQUETE_INFO_PROPRIETAIRE:
            reponse = self.gestionnaire.get_info_proprietaire()
        else:
            return super().traiter_requete(ch, method, properties, body, message_dict)
            # Type de transaction inconnue, on lance une exception
            # raise TransactionTypeInconnuError("Type de transaction inconnue: message: %s" % message_dict, routing_key)

        # Genere message reponse
        if reponse:
            correlation_id = properties.correlation_id
            reply_to = properties.reply_to
            self.transmettre_reponse(message_dict, reponse, replying_to=reply_to, correlation_id=correlation_id)

        return reponse


class TraitementCommandesMaitredesclesProtegees(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        resultat: dict
        if action == ConstantesMaitreDesComptes.COMMANDE_ACTIVATION_TIERCE:
            resultat = self.gestionnaire.set_activation_tierce(message_dict)
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
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesMaitreComptes(self),
        }

        self.__handler_commandes = {
            Constantes.SECURITE_SECURE: TraitementCommandesMaitredesclesProtegees(self),
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
        nom_usager = message_dict[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {
                '$in': [ConstantesMaitreDesComptes.LIBVAL_USAGER, ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE]
            },
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }

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
        date_courante = datetime.datetime.utcnow()

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
        }

        ops = {
            '$set': info_usager,
            '$setOnInsert': set_on_insert,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        collection = self.document_dao.get_collection(self.get_nom_collection_usagers())
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

    def suppression_cles(self, nom_usager: str):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }
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

        return {'ok': True}

    # def associer_idmg(self, nom_usager, idmg, chaine_certificats=None, cle_intermediaire=None, reset_certificats=None):
    #     filtre = {
    #         Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
    #         ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
    #     }
    #
    #     set_ops = {}
    #     document_idmg = {}
    #     if chaine_certificats:
    #         document_idmg[ConstantesMaitreDesComptes.CHAMP_CHAINE_CERTIFICAT] = chaine_certificats
    #     if cle_intermediaire:
    #         document_idmg[ConstantesMaitreDesComptes.CHAMP_CLE] = cle_intermediaire
    #     if reset_certificats:
    #         set_ops['certificats'] = {
    #             idmg: document_idmg
    #         }
    #     else:
    #         set_ops['certificats.%s' % idmg] = document_idmg
    #
    #     ops = {
    #         '$set': set_ops,
    #         '$currentDate': {
    #             Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
    #         }
    #     }
    #
    #     collection = self.document_dao.get_collection(self.get_nom_collection())
    #     resultat = collection.update_one(filtre, ops)
    #     if resultat.matched_count != 1:
    #         raise Exception("Erreur suppression mot de passe, aucun document modifie")
    #
    #     return {Constantes.EVENEMENT_REPONSE: True}

    # def ajouter_certificat_navigateur(self, nom_usager, info_certificat: dict):
    #     filtre = {
    #         Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
    #         ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
    #     }
    #
    #     idmg = info_certificat['idmg']
    #     fingerprint_navigateur = info_certificat['fingerprint']
    #
    #     set_ops = {}
    #     set_ops['idmgs.%s.navigateurs.%s' % (idmg, fingerprint_navigateur)] = {
    #         'cleChiffree': info_certificat['cleChiffree'],
    #         'certificat': info_certificat['certificat'],
    #         'motdepassePartiel': info_certificat['motdepassePartiel'],
    #         'expiration': info_certificat['expiration'],
    #     }
    #
    #     ops = {
    #         '$set': set_ops,
    #         '$currentDate': {
    #             Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
    #         }
    #     }
    #
    #     collection = self.document_dao.get_collection(self.get_nom_collection())
    #     resultat = collection.update_one(filtre, ops)
    #     if resultat.matched_count != 1:
    #         raise Exception("Erreur suppression mot de passe, aucun document modifie")
    #
    #     return {Constantes.EVENEMENT_REPONSE: True}


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

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        self.controleur.gestionnaire.suppression_cles(nom_usager)

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
