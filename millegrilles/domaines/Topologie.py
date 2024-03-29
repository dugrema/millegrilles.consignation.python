# Domaine de topologie des noeuds et domaines
import logging
import json
import datetime

from typing import Optional

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesTopologie
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, TraitementRequetesProtegees
from millegrilles.Domaines import ExchangeRouter, TraitementCommandesProtegees
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.dao.MessageDAO import TraitementMessageDomaine


class TraitementRequetesPrivees(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if routing_key == 'requete.' + ConstantesTopologie.REQUETE_LISTE_APPLICATIONS_DEPLOYEES:
            reponse = {'resultats': self.gestionnaire.get_liste_applications_deployees(message_dict, enveloppe_certificat)}
        else:
            return super().traiter_requete(ch, method, properties, body, message_dict, enveloppe_certificat)
            # Type de transaction inconnue, on lance une exception
            # raise TransactionTypeInconnuError("Type de transaction inconnue: message: %s" % message_dict, routing_key)

        # Genere message reponse
        if reponse:
            correlation_id = properties.correlation_id
            reply_to = properties.reply_to
            self.transmettre_reponse(message_dict, reponse, replying_to=reply_to, correlation_id=correlation_id)

        return reponse


class TraitementRequetesProtegeesTopologie(TraitementRequetesProtegees):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if routing_key == 'requete.' + ConstantesTopologie.REQUETE_LISTE_DOMAINES:
            reponse = {'resultats': self.gestionnaire.get_liste_domaines()}
        elif routing_key == 'requete.' + ConstantesTopologie.REQUETE_LISTE_NOEUDS:
            reponse = {'resultats': self.gestionnaire.get_liste_noeuds(message_dict)}
        elif routing_key == 'requete.' + ConstantesTopologie.REQUETE_INFO_DOMAINE:
            reponse = self.gestionnaire.get_info_domaine(message_dict)
        elif routing_key == 'requete.' + ConstantesTopologie.REQUETE_LISTE_APPLICATIONS_DEPLOYEES:
            reponse = {'resultats': self.gestionnaire.get_liste_applications_deployees(message_dict, enveloppe_certificat)}
        elif routing_key == 'requete.' + ConstantesTopologie.REQUETE_INFO_NOEUD:
            reponse = self.gestionnaire.get_info_noeud(message_dict)
        elif action == ConstantesTopologie.REQUETE_PERMISSION:
            reponse = self.gestionnaire.preparer_permission_dechiffrage_secret(message_dict, properties)
        elif action == ConstantesTopologie.REQUETE_LISTE_NOEUDS_AWSS3:
            reponse = self.gestionnaire.get_noeuds_awss3()
        else:
            super().traiter_requete(ch, method, properties, body, message_dict)
            return

        if reponse is not None:
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class TraitementCommandeTopologie(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        # routing_key = method.routing_key
        #
        # resultat = None
        # if Falserouting_key == 'commande.' + SenseursPassifsConstantes.COMMANDE_RAPPORT_HEBDOMADAIRE:
        #     CommandeGenererRapportHebdomadaire(self.gestionnaire, message_dict).generer()
        # elif routing_key == 'commande.' + SenseursPassifsConstantes.COMMANDE_RAPPORT_ANNUEL:
        #     CommandeGenererRapportAnnuel(self.gestionnaire, message_dict).generer()
        # elif routing_key == 'commande.' + SenseursPassifsConstantes.COMMANDE_DECLENCHER_RAPPORTS:
        #     resultat = CommandeDeclencherRapports(self.gestionnaire, message_dict).declencher()
        # else:
        #     resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class TraitementEvenementsPresence(TraitementMessageDomaine):

    def __init__(self, gestionnaire_domaine):
        super().__init__(gestionnaire_domaine)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def callbackAvecAck(self, ch, method, properties, body):
        super().callbackAvecAck(ch, method, properties, body)

    def traiter_message(self, ch, method, properties, body):
        domaine_action = method.routing_key
        action = domaine_action.split('.')[-1]
        exchange = method.exchange
        lecture = json.loads(body.decode('utf-8'))

        if action == 'monitor':
            self.gestionnaire.enregistrer_presence_monitor(exchange, lecture)
        elif action == 'domaine':
            self.gestionnaire.enregistrer_presence_domaine(exchange, lecture)
        else:
            self.__logger.warning("Type d'annonce de presence inconnu: %s" % domaine_action)


# Gestionnaire pour le domaine millegrilles.domaines.SenseursPassifs.
class GestionnaireTopologie(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__traitement_lecture = None
        self.__traitement_requetes = None
        self._traitement_backlog_lectures = None

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PRIVE: TraitementRequetesPrivees(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesTopologie(self)
        }

        self.__traitement_presence = TraitementEvenementsPresence(self)

        self.__handler_commandes = super().get_handler_commandes()
        self.__handler_commandes[Constantes.SECURITE_PROTEGE] = TraitementCommandeTopologie(self)

    def configurer(self):
        super().configurer()

        # # Ajouter les index dans la collection de transactions
        # collection_transactions = self.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
        # collection_transactions.create_index(
        #     [
        #         (SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE, 2),
        #         ('%s.%s' %
        #          (Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE),
        #          1),
        #         (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        #     ],
        #     name='date-domaine-mglibelle'
        # )

    def get_queue_configuration(self):
        configuration = super().get_queue_configuration()

        configuration.append({
            'nom': '%s.%s' % (self.get_nom_queue(), 'presence'),
            'routing': [
                'evenement.presence.domaine',
            ],
            'exchange': self.configuration.exchange_secure,
            'ttl': 15000,
            'callback': self.__traitement_presence.callbackAvecAck
        })
        configuration.append({
            'nom': '%s.%s' % (self.get_nom_queue(), 'presence'),
            'routing': [
                'evenement.presence.domaine',
            ],
            'exchange': self.configuration.exchange_protege,
            'ttl': 15000,
            'callback': self.__traitement_presence.callbackAvecAck
        })
        configuration.append({
            'nom': '%s.%s' % (self.get_nom_queue(), 'presence'),
            'routing': [
                'evenement.presence.domaine',
            ],
            'exchange': self.configuration.exchange_prive,
            'ttl': 15000,
            'callback': self.__traitement_presence.callbackAvecAck
        })
        configuration.append({
            'nom': '%s.%s' % (self.get_nom_queue(), 'presence'),
            'routing': [
                'evenement.presence.monitor',
            ],
            'exchange': self.configuration.exchange_protege,
            'ttl': 15000,
            'callback': self.__traitement_presence.callbackAvecAck
        })
        configuration.append({
            'nom': '%s.%s' % (self.get_nom_queue(), 'presence'),
            'routing': [
                'evenement.presence.monitor',
            ],
            'exchange': self.configuration.exchange_prive,
            'ttl': 15000,
            'callback': self.__traitement_presence.callbackAvecAck
        })
        configuration.append({
            'nom': '%s.%s' % (self.get_nom_queue(), 'presence'),
            'routing': [
                'evenement.presence.monitor',
            ],
            'exchange': self.configuration.exchange_public,
            'ttl': 15000,
            'callback': self.__traitement_presence.callbackAvecAck
        })

        return configuration

    def demarrer(self):
        super().demarrer()
        # Documents initiaux
        # self.initialiser_document(
        #     SenseursPassifsConstantes.LIBVAL_CONFIGURATION,
        #     SenseursPassifsConstantes.DOCUMENT_DEFAUT_CONFIGURATION
        # )

    def arreter(self):
        super().arreter()

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def get_handler_commandes(self) -> dict:
        return self.__handler_commandes

    def get_nom_queue(self):
        return ConstantesTopologie.QUEUE_NOM

    def get_collection_transaction_nom(self):
        return ConstantesTopologie.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesTopologie.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesTopologie.DOMAINE_NOM

    def traiter_cedule(self, evenement):
        """
        Traite les evenements sur cedule.
        :param evenement:
        :return:
        """
        super().traiter_cedule(evenement)

        # indicateurs = evenement['indicateurs']
        #
        # # Verifier si les indicateurs sont pour notre timezone
        # if 'heure' in indicateurs:
        #     try:
        #         self.traiter_cedule_heure(evenement)
        #     except Exception as he:
        #         self.__logger.exception("Erreur traitement cedule horaire: %s" % str(he))
        #
        #     # Verifier si on a l'indicateur jour pour notre TZ (pas interesse par minuit UTC)
        #     if 'Canada/Eastern' in indicateurs:
        #         if 'jour' in indicateurs:
        #             try:
        #                 self.traiter_cedule_quotidienne(evenement)
        #             except Exception as de:
        #                 self.__logger.exception("Erreur traitement cedule quotidienne: %s" % str(de))

    def get_nom_collection(self):
        return ConstantesTopologie.COLLECTION_DOCUMENTS_NOM

    def identifier_processus(self, domaine_transaction):
        action = domaine_transaction.split('.')[-1]

        if domaine_transaction == ConstantesTopologie.TRANSACTION_DOMAINE:
            processus = "millegrilles_domaines_Topologie:ProcessusTransactionAjouterDomaine"
        elif domaine_transaction == ConstantesTopologie.TRANSACTION_MONITOR:
            processus = "millegrilles_domaines_Topologie:ProcessusTransactionAjouterMonitor"
        elif domaine_transaction == ConstantesTopologie.TRANSACTION_AJOUTER_DOMAINE_DYNAMIQUE:
            processus = "millegrilles_domaines_Topologie:ProcessusTransactionAjouterDomaineDynamique"
        elif domaine_transaction == ConstantesTopologie.TRANSACTION_SUPPRIMER_DOMAINE_DYNAMIQUE:
            processus = "millegrilles_domaines_Topologie:ProcessusTransactionSupprimerDomaineDynamique"
        elif action == ConstantesTopologie.TRANSACTION_CONFIGURER_CONSIGNATION_WEB:
            processus = "millegrilles_domaines_Topologie:ProcessusTransactionConfigurerConsignationWeb"
        else:
            # Type de transaction inconnue, on lance une exception
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def enregistrer_presence_domaine(self, exchange: str, evenement: dict):
        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)

        set_ops = {
            'noeud_id': evenement['noeud_id'],
        }

        filter = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_DOMAINE,
            'domaine': evenement['domaine'],
        }

        on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        on_insert.update(filter)

        ops = {
            '$set': set_ops,
            '$setOnInsert': on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        resultat = collection.update_one(filter, ops, upsert=True)
        if resultat.upserted_id is not None:
            # Creer une transaction pour generer le domaine
            self.soumettre_transaction_domaine(exchange, evenement)

    def soumettre_transaction_domaine(self, exchange, evenement):
        domaine_action = ConstantesTopologie.TRANSACTION_DOMAINE
        transaction = {
            'domaine': evenement['domaine'],
        }
        self.generateur_transactions.soumettre_transaction(transaction, domaine_action)

    def traiter_transaction_domaine(self, transaction):
        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)

        filter = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_DOMAINE,
            'domaine': transaction['domaine'],
        }

        on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        on_insert.update(filter)

        ops = {
            '$setOnInsert': on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        collection.update_one(filter, ops, upsert=True)

    def enregistrer_presence_monitor(self, exchange: str, evenement: dict):
        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)

        securite = evenement.get('securite')
        if securite in [Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]:
            # Evenement de presence d'un sous-noeud, le parent est le noeud protege courant
            parent_id = self.configuration.noeud_id
        elif securite in [Constantes.SECURITE_PROTEGE]:
            # Noeud protege, le parent est responsable de determiner la topologie (si un parent existe)
            parent_id = None
        else:
            parent_id = None

        set_ops = {
            'parent_noeud_id': parent_id,
            'securite': securite,
        }
        for champ in ['fqdn_detecte', 'ip_detectee', 'services', 'containers', 'domaine', 'applications_configurees']:
            valeur = evenement.get(champ)
            if valeur:
                set_ops[champ] = valeur

        # Detecter les applications
        elems_docker = dict()
        if evenement.get('containers'):
            elems_docker.update(evenement.get('containers'))
        if evenement.get('services'):
            elems_docker.update(evenement.get('services'))

        applications = dict()
        for nom, config in elems_docker.items():
            labels = config.get('labels')
            if labels and labels.get('application'):
                nom_application = labels.get('application')
                applications[nom_application] = labels

        set_ops['applications'] = applications

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_NOEUD,
            'noeud_id': evenement['noeud_id'],
        }

        on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        on_insert.update(filtre)

        ops = {
            '$set': set_ops,
            '$setOnInsert': on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        resultat = collection.update_one(filtre, ops, upsert=True)
        if resultat.upserted_id is not None:
            # Creer une transaction pour generer le domaine
            self.soumettre_transaction_monitor(exchange, evenement)

    def soumettre_transaction_monitor(self, exchange, evenement):
        domaine_action = ConstantesTopologie.TRANSACTION_MONITOR
        transaction = {
            'noeud_id': evenement['noeud_id'],
        }
        self.generateur_transactions.soumettre_transaction(transaction, domaine_action)

    def traiter_transaction_monitor(self, transaction):
        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)

        filter = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_NOEUD,
            'noeud_id': transaction['noeud_id'],
        }

        on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        on_insert.update(filter)

        ops = {
            '$setOnInsert': on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        collection.update_one(filter, ops, upsert=True)

    def ajouter_domaine_dynamique(self, transaction: dict):
        noeud_id = transaction['noeud_id']
        nom = transaction['nom']

        set_ops = {
            'domaine': nom,
            'module': transaction['module'],
            'classe': transaction['classe'],
            'actif': True,
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_DOMAINE,
            'noeud_id': noeud_id,
        }

        on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        on_insert.update(filtre)

        ops = {
            '$set': set_ops,
            '$setOnInsert': on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)
        resultat = collection.update_one(filtre, ops, upsert=True)

        # Creer une transaction pour generer/maj le domaine
        self.soumettre_transaction_monitor(Constantes.SECURITE_PROTEGE, transaction)

    def supprimer_domaine_dynamique(self, transaction: dict):
        noeud_id = transaction['noeud_id']
        nom = transaction['nom']

        set_ops = {
            'actif': False,
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_DOMAINE,
            'noeud_id': noeud_id,
            'nom': nom,
        }
        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)
        collection.update_one(filtre, ops)

    def configurer_consignation_web(self, transaction: dict):
        """
        Met a jour la configuration de la consignation web (nginx) du noeud
        :param transaction:
        :return:
        """
        noeud_id = transaction[ConstantesTopologie.CHAMP_NOEUDID]
        filtre = {
            ConstantesTopologie.CHAMP_NOEUDID: noeud_id,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_NOEUD,
        }

        champs = [
            ConstantesTopologie.CHAMP_CONSIGNATION_WEB_MODE,
            ConstantesTopologie.CHAMP_AWSS3_CREDENTIALS_ACCESSID,
            ConstantesTopologie.CHAMP_AWSS3_CREDENTIALS_ACCESSKEY,
            ConstantesTopologie.CHAMP_AWSS3_CREDENTIALS_REGION,
            ConstantesTopologie.CHAMP_AWSS3_BUCKET_REGION,
            ConstantesTopologie.CHAMP_AWSS3_BUCKET_NAME,
            ConstantesTopologie.CHAMP_AWSS3_BUCKET_DIRFICHIER,
        ]
        set_ops = {}
        for champ in champs:
            try:
                champ_set = ConstantesTopologie.CHAMP_CONSIGNATION_WEB + '.' + champ
                set_ops[champ_set] = transaction[champ]
            except KeyError:
                pass  # OK, champ non fourni

        if len(set_ops) == 0:
            raise Exception("Aucun champ recu pour configurer_consignation_web")

        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$set': set_ops,
        }
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur mise a jour configuration consignation web, noeud inexistant : %s" % noeud_id)

    def get_liste_domaines(self):
        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_DOMAINE,
        }
        projection = {
            'domaine': 1,
            'noeud_id': 1,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: 1,
        }
        domaines = list()
        for domaine in collection.find(filtre, projection):
            info_domaine = dict()
            for key, value in domaine.items():
                if key not in ['_id']:
                    info_domaine[key] = value
            domaines.append(info_domaine)

        return domaines

    def get_liste_noeuds(self, params: dict):
        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_NOEUD
        }
        if params.get('noeud_id'):
            filtre['noeud_id'] = params['noeud_id']

        projection = None
        if not params.get('all_info'):
            projection = {
                ConstantesTopologie.CHAMP_NOEUDID: 1,
                'parent_noeud_id': 1,
                Constantes.DOCUMENT_INFODOC_SECURITE: 1,
                'fqdn_detecte': 1,
                'ip_detectee': 1,
                'domaine': 1,
                ConstantesTopologie.CHAMP_CONSIGNATION_WEB: 1,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: 1,
            }

        noeuds = list()
        for noeud in collection.find(filtre, projection):
            info_noeud = dict()
            for key, value in noeud.items():
                if key not in ['_id']:
                    info_noeud[key] = value
            noeuds.append(info_noeud)

        return noeuds

    def get_liste_applications_deployees(self, params: dict, enveloppe_certificat):
        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_NOEUD
        }
        projection = {
            'applications': 1
        }

        exchanges = enveloppe_certificat.get_exchanges
        if Constantes.SECURITE_SECURE in exchanges:
            securite_demande = 4
        elif Constantes.SECURITE_PROTEGE in exchanges:
            securite_demande = 3
        elif Constantes.SECURITE_PRIVE in exchanges:
            securite_demande = 2
        else:
            securite_demande = 1

        # securite = params.get('securite')
        # securite_demande = 2
        # if securite in [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]:
        #     securite_demande = 3

        liste_applications = list()
        for noeud in collection.find(filtre, projection):
            applications = noeud.get('applications')
            if applications:
                for nom_application, info in applications.items():
                    url = info.get('url')
                    securite = info.get('securite')
                    if url and securite:
                        securite_int = int(info['securite'].split('.')[0])
                        if url and securite_int <= securite_demande:
                            liste_applications.append({
                                'application': info.get('application'),
                                'url': url,
                                'securite': info.get('securite')
                            })

        return liste_applications

    def get_info_domaine(self, params: dict):
        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_DOMAINE,
            'domaine': params['domaine']
        }

        info_domaine = collection.find_one(filtre)

        domaine = dict()
        for key, value in info_domaine.items():
            if key not in ['_id']:
                domaine[key] = value

        return domaine

    def get_info_noeud(self, params: dict):
        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_NOEUD,
            'noeud_id': params['noeud_id']
        }
        info_noeud = collection.find_one(filtre)

        noeud = dict()
        for key, value in info_noeud.items():
            if key not in ['_id']:
                noeud[key] = value

        return noeud

    def preparer_permission_dechiffrage_secret(self, requete: dict = None, properties=None):
        permission = {
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_ROLES_PERMIS: ['domaines', 'fichiers'],
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION: (2 * 60),  # 2 minutes
        }

        # Verifier si on "bounce" la requete vers le maitre des cles pour reponse via tiers
        if requete is not None and requete.get('_certificat') is not None:
            if requete.get('identificateurs_document') is not None:
                # Generer une commande de dechiffrage vers le maitre des cles
                domaine_action = Constantes.ConstantesMaitreDesCles.DOMAINE_NOM + '.' + Constantes.ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_DOCUMENT
                requete_rechiffrer = {
                    'identificateurs_document': requete['identificateurs_document'],
                    'domaine': 'Topologie',
                    '_certificat_tiers': requete['_certificat'],
                    'certificat_tiers': requete['_certificat'],
                }
                requete_rechiffrer.update(permission)
                self.generateur_transactions.transmettre_requete(
                    requete_rechiffrer,
                    domaine_action,
                    reply_to=properties.reply_to,
                    correlation_id=properties.correlation_id,
                )
                return

        return permission

    def get_noeuds_awss3(self):
        collection = self.document_dao.get_collection(ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)
        champ_web_awss3 = '.'.join([
            ConstantesTopologie.CHAMP_CONSIGNATION_WEB,
            ConstantesTopologie.CHAMP_CONSIGNATION_WEB_MODE,
        ])
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesTopologie.LIBVAL_NOEUD,
            champ_web_awss3: ConstantesTopologie.VALEUR_AWSS3_CONSIGNATION_WEB_AWSS3,
        }
        projection = {
            ConstantesTopologie.CHAMP_NOEUDID: 1
        }

        curseur = collection.find(filtre, projection=projection)
        noeuds = list()
        for noeud in curseur:
            noeuds.append(noeud['noeud_id'])

        return {'noeud_ids': noeuds}


class ProcessusTopologie(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesTopologie.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesTopologie.COLLECTION_PROCESSUS_NOM


class ProcessusTransactionAjouterDomaine(ProcessusTopologie):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        """
        Enregistrer l'information de la transaction dans le document du senseur
        :return:
        """
        transaction = self.charger_transaction()
        self.__logger.debug("Document processus: %s" % self._document_processus)
        self.__logger.debug("Document transaction: %s" % transaction)

        self._controleur.gestionnaire.traiter_transaction_domaine(transaction)

        self.set_etape_suivante()  # Terminer


class ProcessusTransactionAjouterMonitor(ProcessusTopologie):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        self.__logger.debug("Document processus: %s" % self._document_processus)
        self.__logger.debug("Document transaction: %s" % transaction)

        self._controleur.gestionnaire.traiter_transaction_monitor(transaction)

        self.set_etape_suivante()  # Terminer


class ProcessusTransactionAjouterDomaineDynamique(ProcessusTopologie):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        self.__logger.debug("Document processus: %s" % self._document_processus)
        self.__logger.debug("Document transaction: %s" % transaction)

        self._controleur.gestionnaire.ajouter_domaine_dynamique(transaction)

        self.set_etape_suivante()  # Terminer


class ProcessusTransactionSupprimerDomaineDynamique(ProcessusTopologie):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        self.__logger.debug("Document processus: %s" % self._document_processus)
        self.__logger.debug("Document transaction: %s" % transaction)

        self._controleur.gestionnaire.supprimer_domaine_dynamique(transaction)

        self.set_etape_suivante()  # Terminer


class ProcessusTransactionConfigurerConsignationWeb(ProcessusTopologie):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()

        try:
            self._controleur.gestionnaire.configurer_consignation_web(transaction)
        except Exception as e:
            self.__logger.exception("Erreur traitement ProcessusTransactionConfigurerConsignationWeb")
            return {'err': True, 'message': str(e)}
        finally:
            self.set_etape_suivante()  # Terminer
