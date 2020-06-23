import logging
import datetime

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMessagerie
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesNoeuds,  \
    TransactionTypeInconnuError
from millegrilles.MGProcessus import MGProcessusTransaction


class TraitementRequetesMessageriePrivees(TraitementRequetesNoeuds):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if action == ConstantesMessagerie.REQUETE_CHARGER_COMPTE:
            reponse = self.gestionnaire.charger_compte_usager(message_dict)
        elif action == ConstantesMessagerie.REQUETE_SOMMAIRE_MESSAGES_PAR_IDMG:
            reponse = self.gestionnaire.charger_messages_par_idmg(message_dict[ConstantesMessagerie.CHAMP_IDMGS])
        elif action == ConstantesMessagerie.REQUETE_MESSAGES_USAGER_PAR_SOURCE:
            reponse = self.gestionnaire.charger_messages_usager_par_source(
                message_dict[ConstantesMessagerie.CHAMP_IDMGS_DESTINATION],
                message_dict[ConstantesMessagerie.CHAMP_IDMGS_SOURCE]
            )
        else:
            # Type de transaction inconnue, on lance une exception
            raise TransactionTypeInconnuError("Type de transaction inconnue: message: %s" % message_dict, routing_key)

        return reponse


class GestionnaireMessagerie(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self.__handler_requetes = {
            Constantes.SECURITE_SECURE: TraitementRequetesMessageriePrivees(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesMessageriePrivees(self),
            Constantes.SECURITE_PRIVE: TraitementRequetesMessageriePrivees(self),
        }

        # self.__handler_commandes = {
        #     Constantes.SECURITE_SECURE: TraitementCommandesMaitredesclesProtegees(self),
        #     Constantes.SECURITE_PROTEGE: TraitementCommandesMaitredesclesProtegees(self),
        # }

    def configurer(self):
        super().configurer()

        collection_comptes_usagers = self.document_dao.get_collection(self.get_nom_collection_comptes_usagers())
        collection_comptes_usagers.create_index(
            [
                (ConstantesMessagerie.CHAMP_NOM_USAGER, 1),
            ],
            name='nomusager',
            unique=True,
        )
        collection_comptes_usagers.create_index(
            [
                (ConstantesMessagerie.CHAMP_IDMGS, 1),
            ],
            name='idmgs_connus',
        )

        collection_messages_usagers = self.document_dao.get_collection(self.get_nom_collection_messages_usagers())
        collection_messages_usagers.create_index(
            [
                (ConstantesMessagerie.CHAMP_IDMG_DESTINATION, 1),
                (ConstantesMessagerie.CHAMP_DATE_ENVOI, -1),
            ],
            name='idmgdest_date',
        )

    def demarrer(self):
        super().demarrer()
        # self.initialiser_document(ConstantesMaitreDesCles.LIBVAL_CONFIGURATION, ConstantesMaitreDesCles.DOCUMENT_DEFAUT)

    def identifier_processus(self, domaine_transaction):

        action = domaine_transaction.split('.')[-1]

        if action == ConstantesMessagerie.TRANSACTION_INSCRIRE_COMPTE:
            processus = "millegrilles_domaines_Messagerie:ProcessusInscrireCompte"
        elif action == ConstantesMessagerie.TRANSACTION_AJOUTER_IDMGS_COMPTE:
            processus = "millegrilles_domaines_Messagerie:ProcessusAjouterIdmgsCompte"
        elif action == ConstantesMessagerie.TRANSACTION_ENVOYER_MESSAGE:
            processus = "millegrilles_domaines_Messagerie:ProcessusEnvoyerMessage"
        elif action == ConstantesMessagerie.TRANSACTION_MARQUER_MESSAGE_LU:
            processus = "millegrilles_domaines_Messagerie:ProcessusMarquerMessageLu"
        elif action == ConstantesMessagerie.TRANSACTION_SUPPRIMER_MESSAGE:
            processus = "millegrilles_domaines_Messagerie:ProcessusSupprimerMessage"
        elif action == ConstantesMessagerie.TRANSACTION_MODIFIER_CONTACT:
            processus = "millegrilles_domaines_Messagerie:ProcessusModifierContact"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes

    #def get_handler_commandes(self) -> dict:
    #    return self.__handler_commandes

    def get_nom_collection(self):
        return ConstantesMessagerie.COLLECTION_DOCUMENTS_NOM

    def get_nom_collection_comptes_usagers(self):
        return ConstantesMessagerie.COLLECTION_COMPTES_USAGERS_NOM

    def get_nom_collection_messages_usagers(self):
        return ConstantesMessagerie.COLLECTION_MESSAGES_USAGERS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesMessagerie.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesMessagerie.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesMessagerie.DOMAINE_NOM

    def get_nom_queue(self):
        return ConstantesMessagerie.QUEUE_NOM

    def charger_compte_usager(self, params: dict):
        collection_comptes = self.document_dao.get_collection(self.get_nom_collection_comptes_usagers())
        filtre = {
            ConstantesMessagerie.CHAMP_NOM_USAGER: params[ConstantesMessagerie.CHAMP_NOM_USAGER]
        }

        compte_usager = collection_comptes.find_one(filtre)

        return compte_usager

    def inscrire_compte_usager(self, params: dict):
        collection_comptes = self.document_dao.get_collection(self.get_nom_collection_comptes_usagers())
        filtre = {
            ConstantesMessagerie.CHAMP_NOM_USAGER: params[ConstantesMessagerie.CHAMP_NOM_USAGER]
        }
        date_courante = datetime.datetime.utcnow()

        set_ops = {
            ConstantesMessagerie.CHAMP_NOM_USAGER: params[ConstantesMessagerie.CHAMP_NOM_USAGER],
            ConstantesMessagerie.CHAMP_IDMGS: params[ConstantesMessagerie.CHAMP_IDMGS],
        }

        ops = {
            '$set': set_ops,
            '$setOnInsert': {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMessagerie.LIBVAL_COMPTE_USAGER,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante
            },
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        resultat = collection_comptes.update_one(filtre, ops, upsert=True)
        if not resultat.upserted_id and resultat.matched_count == 0:
            raise Exception("Erreur inscription, aucun document modifie")

    def charger_messages_par_idmg(self, idmgs: list):
        collection_messages = self.document_dao.get_collection(self.get_nom_collection_messages_usagers())
        filtre = {
            ConstantesMessagerie.CHAMP_IDMG_DESTINATION: {'$in': idmgs}
        }

        curseur_messages = collection_messages.find(filtre)
        messages = list()
        for m in curseur_messages:
            del m[Constantes.MONGO_DOC_ID]
            messages.append(m)

        return messages

    def charger_messages_usager_par_source(self, idmgs_usager: list, idmgs_source: list):
        collection_messages = self.document_dao.get_collection(self.get_nom_collection_messages_usagers())
        filtre = {
            '$or': [
                {
                    ConstantesMessagerie.CHAMP_IDMG_DESTINATION: {'$in': idmgs_usager},
                    ConstantesMessagerie.CHAMP_IDMG_SOURCE: {'$in': idmgs_source},
                }, {
                    ConstantesMessagerie.CHAMP_IDMG_DESTINATION: {'$in': idmgs_source},
                    ConstantesMessagerie.CHAMP_IDMG_SOURCE: {'$in': idmgs_usager},
                }
            ]
        }

        tri = [
            (ConstantesMessagerie.CHAMP_DATE_ENVOI, -1)
        ]

        curseur_messages = collection_messages.find(filtre).sort(tri).limit(30)
        messages = list()
        for m in curseur_messages:
            del m[Constantes.MONGO_DOC_ID]
            messages.append(m)

        # Les messages sont tries en ordre descendant (date) - on remet en ordre
        messages.reverse()

        return messages

    def envoyer_message(self, transaction: dict):
        collection_messages = self.document_dao.get_collection(self.get_nom_collection_messages_usagers())

        date_courante = datetime.datetime.utcnow()

        entete_transaction = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]

        message = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: entete_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
            ConstantesMessagerie.CHAMP_DATE_ENVOI: datetime.datetime.fromtimestamp(entete_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]),
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_courante,
            Constantes.DOCUMENT_INFODOC_SECURITE: transaction[Constantes.DOCUMENT_INFODOC_SECURITE],

            ConstantesMessagerie.CHAMP_IDMG_SOURCE: transaction[ConstantesMessagerie.CHAMP_IDMG_SOURCE],
            ConstantesMessagerie.CHAMP_IDMG_DESTINATION: transaction[ConstantesMessagerie.CHAMP_IDMG_DESTINATION],
        }

        message_instantane = transaction.get(ConstantesMessagerie.CHAMP_MESSAGE)
        if message_instantane:
            message[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesMessagerie.LIBVAL_MESSAGE_INSTANTANNE
            message[ConstantesMessagerie.CHAMP_MESSAGE] = transaction[ConstantesMessagerie.CHAMP_MESSAGE]
        else:
            message[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesMessagerie.LIBVAL_MESSAGE_COURRIEL
            message[ConstantesMessagerie.CHAMP_SUJET] = transaction[ConstantesMessagerie.CHAMP_SUJET]
            message[ConstantesMessagerie.CHAMP_CONTENU] = transaction[ConstantesMessagerie.CHAMP_CONTENU]

        collection_messages.insert_one(message)

    def marquer_message_lu(self, uuid_message: str):
        collection_messages = self.document_dao.get_collection(self.get_nom_collection_messages_usagers())

        filtre = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_message
        }
        ops = {
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
                ConstantesMessagerie.CHAMP_DATE_LECTURE: True
            },
        }

        resultat = collection_messages.update_one(filtre, ops, upsert=False)
        if not resultat.upserted_id and resultat.matched_count == 0:
            raise Exception("Erreur inscription, aucun document modifie")

    def supprimer_message(self, uuid_message: str):
        collection_messages = self.document_dao.get_collection(self.get_nom_collection_messages_usagers())

        filtre = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_message
        }
        resultat = collection_messages.delete_one(filtre)
        if not resultat.deleted_count == 1:
            raise Exception("Erreur suppression message, aucun document trouve pour uuid: %s", uuid_message)

    def modifier_contact(self, transaction: dict):
        collection_comptes = self.document_dao.get_collection(self.get_nom_collection_comptes_usagers())

        label_contact = '%s.%s' % (ConstantesMessagerie.CHAMP_CONTACTS, transaction[ConstantesMessagerie.CHAMP_UUID_CONTACT])
        operation_supprimer = transaction.get(ConstantesMessagerie.CHAMP_SUPPRIMER)

        ops = {
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
            },
        }

        if not operation_supprimer:
            ops['$set'] = {
                label_contact: {
                    ConstantesMessagerie.CHAMP_NOM_CONTACT: transaction[ConstantesMessagerie.CHAMP_NOM_CONTACT],
                    ConstantesMessagerie.CHAMP_IDMGS: transaction[ConstantesMessagerie.CHAMP_IDMGS],
                }
            }
        else:
            ops['$unset'] = {label_contact: True}

        filtre = {
            ConstantesMessagerie.CHAMP_NOM_USAGER: transaction[ConstantesMessagerie.CHAMP_NOM_USAGER]
        }

        resultat = collection_comptes.update_one(filtre, ops, upsert=True)
        if not resultat.upserted_id and resultat.matched_count == 0:
            raise Exception("Erreur maj contact, aucun document modifie")


class ProcessusInscrireCompte(MGProcessusTransaction):
    """
    Permet au proprietaire de prendre possession de sa MilleGrille.
    """
    def initiale(self):
        transaction = self.transaction_filtree
        self.controleur.gestionnaire.inscrire_compte_usager(transaction)
        self.set_etape_suivante()  # Termine


class ProcessusEnvoyerMessage(MGProcessusTransaction):
    """
    Envoit un nouveau message
    """
    def initiale(self):
        transaction = self.transaction
        self.controleur.gestionnaire.envoyer_message(transaction)
        self.set_etape_suivante()  # Termine


class ProcessusMarquerMessageLu(MGProcessusTransaction):
    """
    Marque un message lu
    """
    def initiale(self):
        transaction = self.transaction
        uuid_message = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        self.controleur.gestionnaire.marquer_message_lu(uuid_message)
        self.set_etape_suivante()  # Termine


class ProcessusSupprimerMessage(MGProcessusTransaction):
    """
    Supprime un message
    """
    def initiale(self):
        transaction = self.transaction
        uuid_message = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        self.controleur.gestionnaire.supprimer_message(uuid_message)
        self.set_etape_suivante()  # Termine


class ProcessusModifierContact(MGProcessusTransaction):
    """
    Ajoute ou modifie un contact pour un usager
    """
    def initiale(self):
        transaction = self.transaction
        self.controleur.gestionnaire.modifier_contact(transaction)
        self.set_etape_suivante()  # Termine
