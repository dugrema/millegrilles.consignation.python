# Domaine MaitreDesCles
# Responsable de la gestion et de l'acces aux cles secretes pour les niveaux 3.Protege et 4.Secure.

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMaitreDesCles, ConstantesSecurite
from millegrilles.Domaines import GestionnaireDomaineStandard, TransactionTypeInconnuError, \
    TraitementMessageDomaineRequete, TraitementRequetesProtegees, TraitementCommandesProtegees, \
    TraitementCommandesSecures
from millegrilles.MGProcessus import MGProcessusTransaction, MGProcessus
from millegrilles.util.X509Certificate import EnveloppeCleCert, \
    ConstantesGenerateurCertificat, RenouvelleurCertificat, PemHelpers
from millegrilles.domaines.Pki import ConstantesPki
from millegrilles.SecuritePKI import EnveloppeCertificat
from millegrilles.util.BackupModule import HandlerBackupDomaine

from cryptography.hazmat.backends import default_backend
from cryptography import x509
from base64 import b64encode, b64decode
from typing import Optional
from os import path, listdir

import logging
import datetime
import re
import multibase
import pytz


class TraitementRequetesPrivees(TraitementMessageDomaineRequete):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat: EnveloppeCertificat):
        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        action = method.routing_key.split('.')[-1]

        # S'assurer que le certificat a au moins le role prive
        securite_permise = set(ConstantesSecurite.cascade_secure(Constantes.SECURITE_PRIVE))
        securite_cert = set(enveloppe_certificat.get_exchanges)
        if len(securite_cert.intersection(securite_permise)) == 0:
            return {'ok': False, Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_CLE_INCONNUE}

        reponse = None
        if action == ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES:
            # Transmettre le certificat courant du maitre des cles
            self.gestionnaire.transmettre_certificat(properties)
            return
        elif action == ConstantesMaitreDesCles.REQUETE_DECHIFFRAGE:
            reponse = self.gestionnaire.transmettre_cle(message_dict, properties, enveloppe_certificat)
        else:
            # Type de transaction inconnue, on lance une exception
            raise TransactionTypeInconnuError("Type de transaction inconnue: message: %s" % message_dict, routing_key)

        if reponse is not None:
            try:
                self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
            except Exception:
                self.__logger.exception("Erreur transmission reponse %s" % reponse)


class TraitementRequetesNoeuds(TraitementMessageDomaineRequete):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        # S'assurer que le certificat a au moins le role protege
        securite_permise = set(ConstantesSecurite.cascade_secure(Constantes.SECURITE_PROTEGE))
        securite_cert = set(enveloppe_certificat.get_exchanges)
        if len(securite_cert.intersection(securite_permise)) == 0:
            return {'ok': False, Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_CLE_INCONNUE}

        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        routing_key_sansprefixe = routing_key.replace(
            'requete.%s.' % ConstantesMaitreDesCles.DOMAINE_NOM,
            ''
        )

        if routing_key_sansprefixe == ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES:
            # Transmettre le certificat courant du maitre des cles
            self.gestionnaire.transmettre_certificat(properties)
        else:
            # Type de transaction inconnue, on lance une exception
            raise TransactionTypeInconnuError("Type de transaction inconnue: message: %s" % message_dict, routing_key)


class TraitementRequetesMaitreDesClesProtegees(TraitementRequetesProtegees):

    def __init__(self, gestionnaire_domaine):
        super().__init__(gestionnaire_domaine)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        # S'assurer que le certificat a au moins le role protege
        securite_permise = set(ConstantesSecurite.cascade_secure(Constantes.SECURITE_PROTEGE))
        securite_cert = set(enveloppe_certificat.get_exchanges)
        if len(securite_cert.intersection(securite_permise)) == 0:
            return {'ok': False, Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_CLE_INCONNUE}

        action = method.routing_key.split('.')[-1]

        reponse = None
        if action == ConstantesMaitreDesCles.REQUETE_DECHIFFRAGE:
            reponse = self.gestionnaire.transmettre_cle(message_dict, properties, enveloppe_certificat)
        elif action == ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES:
            self.gestionnaire.transmettre_certificat(properties)
        elif action == ConstantesMaitreDesCles.REQUETE_CLES_NON_DECHIFFRABLES:
            reponse = self.gestionnaire.transmettre_cles_non_dechiffrables(message_dict)
        elif action == ConstantesMaitreDesCles.REQUETE_COMPTER_CLES_NON_DECHIFFRABLES:
            reponse = self.gestionnaire.compter_cles_non_dechiffrables(message_dict)
        else:
            reponse = super().traiter_requete(ch, method, properties, body, message_dict)

        if reponse is not None:
            try:
                self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
            except Exception:
                self.__logger.exception("Erreur transmission reponse %s" % reponse)


class TraitementCommandesMaitreDesClesProtegees(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        # S'assurer que le certificat a au moins le role protege
        securite_permise = set(ConstantesSecurite.cascade_secure(Constantes.SECURITE_PROTEGE))
        securite_cert = set(enveloppe_certificat.get_exchanges)
        if len(securite_cert.intersection(securite_permise)) == 0:
            return {'ok': False, Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_CLE_INCONNUE}

        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        resultat: dict
        if routing_key == 'commande.%s.%s' % (
            ConstantesMaitreDesCles.DOMAINE_NOM, ConstantesMaitreDesCles.COMMANDE_RESTAURER_BACKUP_CLES):
                resultat = self.gestionnaire.restaurer_backup_cles(properties, message_dict)
        elif action == ConstantesMaitreDesCles.COMMANDE_SAUVEGARDER_CLE:
            resultat = self.gestionnaire.sauvegarder_cle(message_dict, properties)
        else:
            resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class TraitementCommandesMaitreDesClesSecures(TraitementCommandesSecures):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        # S'assurer que le certificat a au moins le role protege
        securite_permise = set(ConstantesSecurite.cascade_secure(Constantes.SECURITE_SECURE))
        securite_cert = set(enveloppe_certificat.get_exchanges)
        if len(securite_cert.intersection(securite_permise)) == 0:
            return {'ok': False, Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_CLE_INCONNUE}

        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if action == ConstantesMaitreDesCles.COMMANDE_SAUVEGARDER_CLE:
            resultat = self.gestionnaire.sauvegarder_cle(message_dict)
        else:
            resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class GestionnaireMaitreDesCles(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self.__nomfichier_autorite_cert = self.configuration.pki_config[Constantes.CONFIG_PKI_CERT_MILLEGRILLE]
        self.__clecert_intermediaire = None  # Cle et certificat de millegrille
        self.__certificat_intermediaires_pem = None
        self.__certificat_millegrille: Optional[EnveloppeCertificat] = None
        self.__certificats_backup = dict()  # Liste de certificats backup utilises pour conserver les cles secretes.
        self.__ca_file_pem = None
        self.__dict_ca = None  # Key=akid, Value=x509.Certificate()

        # Liste de tous les clecerts qui sont disponibles pour dechiffrer (e.g. cles de vieux certificats)
        self.__clecert_historique: Optional[list] = None

        self.__renouvelleur_certificat = None

        # Queue message handlers
        self.__handler_requetes = {
            Constantes.SECURITE_SECURE: TraitementRequetesMaitreDesClesProtegees(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesMaitreDesClesProtegees(self),
            Constantes.SECURITE_PRIVE: TraitementRequetesPrivees(self),
            Constantes.SECURITE_PUBLIC: TraitementRequetesNoeuds(self),
        }

        self.__handler_commandes = super().get_handler_commandes()
        self.__handler_commandes[Constantes.SECURITE_PROTEGE] = TraitementCommandesMaitreDesClesProtegees(self)
        self.__handler_commandes[Constantes.SECURITE_SECURE] = TraitementCommandesMaitreDesClesSecures(self)

        self.__encryption_helper = None
        self.__handler_backup = HandlerBackupMaitreDesCles(self._contexte)

    def configurer(self):
        super().configurer()

        self.charger_ca_chaine()

        # Faire une demande pour charger les certificats de backup courants
        self.demander_certificats_backup()

        # Index collection domaine
        collection_domaine = self.get_collection()

        # Index par identificateurs_documents, domaine
        collection_domaine.create_index(
            [
                (ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS, 1),
                (Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE, 1),
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1),
            ],
            name='domaine-libelle',
            unique=True,
        )

        collection_cles = self._contexte.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_CLES_NOM)

        # Index d'acces par hachage (methode principale pour dechiffrer du contenu)
        collection_cles.create_index(
            [
                (ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES, 1)
            ],
            name='hachage_bytes',
            unique=True,
        )

        # Index pour trouver rapidement cles non dechiffrables
        collection_cles.create_index(
            [
                (ConstantesMaitreDesCles.TRANSACTION_CHAMP_NON_DECHIFFRABLE, 1),
                (Constantes.DOCUMENT_INFODOC_DATE_CREATION, 1),
            ],
            name='flag_non_dechiffrable',
        )

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesMaitreDesCles.LIBVAL_CONFIGURATION, ConstantesMaitreDesCles.DOCUMENT_DEFAUT)

    def executer_entretien(self):
        super().executer_entretien()
        self.rechiffrer_cles_apres_rotation()

    def charger_ca_chaine(self):
        self.__dict_ca = dict()

        self._logger.info("CA FILE: %s" % self.configuration.pki_cafile)
        ca_file = self.configuration.pki_cafile
        with open(ca_file, 'rb') as fichier:
            cert = fichier.read()
            self.__ca_file_pem = cert.decode('utf-8')
            x509_cert = x509.load_pem_x509_certificate(cert, backend=default_backend())
            skid = EnveloppeCleCert.get_subject_identifier(x509_cert)
            self.__dict_ca[skid] = x509_cert
            self.__certificat_millegrille = EnveloppeCertificat(certificat_pem=cert)

        self._logger.info("Cert maitre des cles: %s" % self.configuration.pki_certfile)
        with open(self.configuration.pki_certfile, 'r') as fichier:
            chaine = fichier.read()
            chaine = PemHelpers.split_certificats(chaine)

            # Prendre tous les certificats apres le premier (c'est celui du maitre des cles)
            for cert in chaine[1:]:
                x509_cert = x509.load_pem_x509_certificate(cert.encode('utf-8'), backend=default_backend())
                skid = EnveloppeCleCert.get_subject_identifier(x509_cert)
                self.__dict_ca[skid] = x509_cert

        # Parcourir le repertoire de cles pour trouver toutes les cles avec une date (e.g. key.pem.20210117191956)
        p = re.compile('key.pem.[0-9]+|pki.maitrecles.key.[0-9]+')
        path_cle = path.dirname(self.configuration.pki_keyfile)
        self.__clecert_historique = list()
        for fichier in listdir(path_cle):
            if p.match(fichier):
                self._logger.info("Charger cle historique %s" % fichier)
                clecert = EnveloppeCleCert()
                with open(path.join(path_cle, fichier), 'rb') as fp:
                    clecert.key_from_pem_bytes(fp.read())
                    self.__clecert_historique.append(clecert)

    def demander_certificats_backup(self):
        requete = {}
        domaine = '%s.%s' % (ConstantesPki.DOMAINE_NOM, ConstantesPki.REQUETE_CERTIFICAT_BACKUP)
        queue = '%s.commande.4.secure' % ConstantesMaitreDesCles.QUEUE_NOM
        self.generateur_transactions.transmettre_requete(
            requete,
            domaine,
            correlation_id=ConstantesMaitreDesCles.CORRELATION_CERTIFICATS_BACKUP,
            reply_to=queue,
            securite=Constantes.SECURITE_SECURE,
        )

    def verifier_certificats_backup(self, message_dict):
        """
        Charge les certificats de backup presents dans le repertoire des certificats.
        Les cles publiques des backups sont utilisees pour re-encrypter les cles secretes.
        :return:
        """
        certificats = message_dict.get('certificats') or message_dict['resultats']['certificats']

        validateur_pki = self.validateur_pki
        for fingerprint_hex, certificat in certificats.items():

            enveloppe = validateur_pki.valider(certificat)
            # enveloppe = EnveloppeCertificat(certificat_pem=certificat)
            fingerprint_b64 = EnveloppeCertificat.calculer_fingerprint_b64(enveloppe.certificat)

            # Verifier que c'est un certificat du bon type
            roles_acceptes = [
                ConstantesGenerateurCertificat.ROLE_BACKUP, ConstantesGenerateurCertificat.ROLE_MAITREDESCLES
            ]
            if any([role in roles_acceptes for role in enveloppe.get_roles]):
                # resultat_verification = verificateur_certificats.verifier_chaine(enveloppe)
                resultat_verification = validateur_pki.valider(certificat)
                if resultat_verification:
                    self.__certificats_backup[fingerprint_b64] = enveloppe
            else:
                self._logger.warning("Certificat fournit pour backup n'a pas le role 'backup' : fingerprint hex " + fingerprint_hex)

        processus = "millegrilles_domaines_MaitreDesCles:ProcessusTrouverClesBackupManquantes"
        fingerprints_backup = {'fingerprints_base64': list(self.__certificats_backup.keys())}
        self.demarrer_processus(processus, fingerprints_backup)

    def identifier_processus(self, domaine_transaction):

        domaine_action = domaine_transaction.split('.')[-1]

        if domaine_action == ConstantesMaitreDesCles.TRANSACTION_CLE:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCle"

        # if domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_GROSFICHIER:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCleGrosFichier"
        # elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_BACKUPTRANSACTIONS:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCleBackupTransaction"
        # elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_DOCUMENT:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCleDocument"
        # elif domaine_action == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_DOCUMENT_BACKUP:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCleDocumentBackup"
        # elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_MAJ_DOCUMENT_CLES:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusMAJDocumentCles"
        # elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_MAJ_MOTDEPASSE:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusMAJMotdepasse"
        # elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_DECLASSER_CLE_GROSFICHIER:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusDeclasserCleGrosFichier"

        # elif domaine_action == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_GROSFICHIER_BACKUP:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusCleGrosfichierBackup"
        # elif domaine_action == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_BACKUPTRANSACTIONS_BACKUP:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCleBackupTransactionBackup"
        # elif domaine_action == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_BACKUPAPPLICATION:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCleBackupApplication"
        # elif domaine_action == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_BACKUPAPPLICATION_BACKUP:
        #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCleBackupApplicationBackup"

        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def decrypter_contenu(self, contenu):
        """
        Utilise la cle privee en memoire pour decrypter le contenu.
        :param contenu:
        :return:
        """
        return self._contexte.signateur_transactions.dechiffrage_asymmetrique(contenu)

    def decrypter_cle(self, dict_cles):
        """
        Decrypte la cle secrete en utilisant la cle prviee d'un certificat charge en memoire
        :param dict_cles: Dictionnaire de cles secretes cryptes, la cle_dict est le fingerprint du certificat
        :return:
        """
        enveloppe = self._contexte.signateur_transactions.enveloppe_certificat_courant
        fingerprint_courant = enveloppe.fingerprint
        cle_secrete_cryptee = dict_cles.get(fingerprint_courant)
        if cle_secrete_cryptee is not None:
            # On peut decoder la cle secrete
            return self.decrypter_contenu(cle_secrete_cryptee)
        else:
            return None

    def decrypter_motdepasse(self, dict_cles):
        """
        Decrypte un mot de passe en trouvant la cle correspondante
        :param dict_cles: Dictionnaire de mots de passes cryptes, la key est le fingerprint du certificat
        :return:
        """
        enveloppe = self._contexte.signateur_transactions.enveloppe_certificat_courant
        fingerprint_courant = enveloppe.fingerprint_b64
        cle_secrete_cryptee = dict_cles.get(fingerprint_courant)
        if cle_secrete_cryptee is not None:
            # On peut decoder la cle secrete
            motdepasse = self.decrypter_contenu(cle_secrete_cryptee)
            return b64encode(motdepasse)
        else:
            return None

    def decrypter_grosfichier(self, fuuid):
        """
        Verifie si la requete de cle est valide, puis transmet une reponse en clair.
        Le fichier est maintenant declasse, non protege.
        :param fuuid:
        :return:
        """
        collection_documents = self.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesCles.DOCUMENT_LIBVAL_CLES_GROSFICHIERS,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                'fuuid': fuuid,
            }
        }
        document = collection_documents.find_one(filtre)
        # Note: si le document n'est pas trouve, on repond acces refuse (obfuscation)
        reponse = {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_REFUSE}
        if document is not None:
            self._logger.debug("Document de cles pour grosfichiers: %s" % str(document))
            cle_secrete = self.decrypter_cle(document['cles'])
            reponse = {
                'cle_secrete_decryptee': b64encode(cle_secrete).decode('utf-8'),
                'iv': document['iv'],
                Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_PERMIS
            }

        return reponse

    # def generer_certificat_connecteur(self, idmg_tiers, csr) -> EnveloppeCleCert:
    #     # Trouver generateur pour le role
    #     renouvelleur = self.renouvelleur_certificat
    #     certificat = renouvelleur.signer_connecteur_tiers(idmg_tiers, csr)
    #     clecert = EnveloppeCleCert(cert=certificat)
    #
    #     return clecert

    # def transmettre_cle_racine(self, properties, message_dict: dict):
    #     self._logger.debug("Preparation transmission de la cle Racine, requete : %s" % str(message_dict))
    #
    #     # Verifier que le demandeur a l'autorisation de se faire transmettre la cle racine
    #     en_tete = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
    #     fingerprint_demandeur = en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT]
    #     certificat_demandeur = self._contexte.verificateur_certificats.charger_certificat(fingerprint=fingerprint_demandeur)
    #     exchanges_certificat = certificat_demandeur.get_exchanges
    #     roles_certificat = certificat_demandeur.get_roles
    #
    #     exchanges_acceptes = [ConstantesSecurite.EXCHANGE_PROTEGE, ConstantesSecurite.EXCHANGE_SECURE]
    #     roles_acceptes = [
    #         ConstantesGenerateurCertificat.ROLE_MAITREDESCLES,
    #         ConstantesGenerateurCertificat.ROLE_COUPDOEIL_NAVIGATEUR,
    #         ConstantesGenerateurCertificat.ROLE_COUPDOEIL
    #     ]
    #     if not any(exchange in exchanges_acceptes for exchange in exchanges_certificat):
    #         raise Exception("Certificat %s non autorise a recevoir cle racine (exchange)" % fingerprint_demandeur)
    #     if not any(exchange in roles_acceptes for exchange in roles_certificat):
    #         raise Exception("Certificat %s non autorise a recevoir cle racine (role)" % fingerprint_demandeur)
    #
    #     with open(self.configuration.pki_cafile, 'r') as fichier:
    #         fichier_cert_racine = fichier.read()
    #
    #     with open(self.configuration.pki_keymillegrille, 'rb') as fichier:
    #         fichier_key_racine = fichier.read()
    #
    #     with open(self.configuration.pki_password_millegrille, 'rb') as fichier:
    #         password_millegrille = fichier.read()
    #
    #     clecert = EnveloppeCleCert()
    #     clecert.key_from_pem_bytes(fichier_key_racine, password_millegrille)
    #
    #     # Dechiffrer le mot de passe demande pour le retour de la cle privee chiffree
    #     mot_de_passe_chiffre = message_dict['mot_de_passe_chiffre']
    #     mot_de_passe_dechiffre = self.decrypter_contenu(mot_de_passe_chiffre)
    #     clecert.password = mot_de_passe_dechiffre
    #     cle_privee_chiffree = clecert.private_key_bytes
    #
    #     return {
    #         'cle_racine': cle_privee_chiffree.decode('utf-8'),
    #         'cert_racine': fichier_cert_racine,
    #     }

    def transmettre_cle(self, evenement: dict, properties, enveloppe_certificat):
        """
        Verifie si la requete de cle est valide, puis transmet une reponse (cle re-encryptee ou acces refuse)
        :param evenement:
        :param properties:
        :return:
        """
        self._logger.debug("Transmettre cle a %s" % properties.reply_to)

        # Verifier que la signature de la requete est valide - c'est fort probable, il n'est pas possible de
        # se connecter a MQ sans un certificat verifie. Mais s'assurer qu'il n'y ait pas de "relais" via un
        # messager qui a acces aux noeuds. La signature de la requete permet de faire cette verification.
        enveloppe_evenement = self.extraire_certificat(evenement)

        try:
            permission = evenement['permission']
            enveloppe_permission = self.extraire_certificat(permission)
        except KeyError:
            permission = evenement
            enveloppe_permission = enveloppe_evenement

        hachage_bytes_permission = permission.get(ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES)
        if hachage_bytes_permission is not None:
            hachage_bytes_permission = set(hachage_bytes_permission)
        else:
            hachage_bytes_permission = None
        identificateurs_documents = permission.get(ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS)
        domaines_permis = None
        user_id_permis = None
        securite_permise = None

        if evenement.get('permission'):
            self._logger.debug("Verification de permission pour dechiffrer une cle : %s" % permission)

            if Constantes.SECURITE_SECURE in enveloppe_permission.get_exchanges:
                # Un certificat 4.secure peut donner acces a n'importe quel domaine
                domaines_permis = permission.get('roles_permis')
                user_id_permis = permission.get('user_id')
                securite_permise = permission.get(Constantes.DOCUMENT_INFODOC_SECURITE)
            elif Constantes.SECURITE_PROTEGE in enveloppe_permission.get_exchanges:
                # Faire l'intersection entre les roles du certificat de la permission et les roles explicitement permis
                # Evite de donner acces a un role que le certificat d'origine n'as pas acces
                set_domaines_evenement = set(enveloppe_permission.get_roles)
                set_domaines_permis = set(permission.get('roles_permis'))
                domaines_permis = list(set_domaines_evenement.intersection(set_domaines_permis))
                user_id_permis = permission.get('user_id')
                securite_permise = permission.get(Constantes.DOCUMENT_INFODOC_SECURITE)
            else:
                self._logger.debug("Une permission ne peut pas etre donnee par "
                                   "un certificat 1.public ou 2.prive : %s" % permission)
                return {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_REFUSE}

            # Par defaut, 30 minutes pour une permission
            # Verifier si la validite de la permission de dechiffrage est expiree
            estampille_evenement = permission[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
            duree_permission = permission.get(ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION) or (30 * 60)
            date_estampille_evenement = datetime.datetime.fromtimestamp(estampille_evenement, tz=pytz.utc)

            date_expiration = pytz.utc.localize(datetime.datetime.utcnow()) - datetime.timedelta(seconds=duree_permission)

            if date_estampille_evenement > date_expiration:
                # Extraire certificats de rechiffrage
                rechiffrage_pems = \
                    evenement.get('_certificat_tiers') or \
                    evenement.get('certificat_tiers') or \
                    evenement.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT_INCLUS)
                if rechiffrage_pems is not None:
                    enveloppe_rechiffrage = self.validateur_pki.valider(rechiffrage_pems)
                else:
                    enveloppe_rechiffrage = enveloppe_certificat
            else:
                self._logger.debug("Permission expiree : %s" % evenement)
                return {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_REFUSE}

            if user_id_permis is not None:
                # Verifier que le certificat de la requete est du bon user id
                enveloppe_user_id = enveloppe_evenement.get_user_id
                if enveloppe_user_id is None or enveloppe_user_id != user_id_permis:
                    self._logger.debug("Requete du mauvais user_id : %s" % evenement)
                    return {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_REFUSE}

            if securite_permise is not None:
                exchanges_user = enveloppe_evenement.get_exchanges
                if securite_permise not in exchanges_user:
                    return {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_REFUSE}

        else:
            self._logger.debug("Verification de certificat pour dechiffrer une cle : %s" % evenement)

            # Verifier le niveau d'acces (exchange)
            exchanges = enveloppe_evenement.get_exchanges

            if Constantes.SECURITE_SECURE in exchanges:
                # Le certificat donne acces a toutes les cles sans verification supplementaire
                enveloppe_rechiffrage = enveloppe_evenement
            elif Constantes.SECURITE_PROTEGE in exchanges:
                # Niveau protege, verifier si on a une permission speciale inclue dans la demande
                domaines_permis = enveloppe_evenement.get_roles
                enveloppe_rechiffrage = enveloppe_evenement
            else:
                self._logger.debug("Le dechiffrage ne peut etre demande directement par un certificat "
                                   "1.public ou 2.prive : %s" % evenement)
                return {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_REFUSE}

        # Conserver tous les hachages bytes demandes qui sont inclus dans la permission (et rejeter les autres)
        filtre = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: {'$in': domaines_permis}
        }
        if hachage_bytes_permission is not None:
            hachages_bytes_demandes = set(evenement[ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES]).intersection(hachage_bytes_permission)
            filtre[ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES] = {
                '$in': list(hachages_bytes_demandes)
            }

        if identificateurs_documents is not None:
            for key, value in identificateurs_documents.items():
                filtre[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS + '.' + key] = value
            hachages_bytes_demandes = evenement[ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES]
            filtre[ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES] = {
                '$in': list(hachages_bytes_demandes)
            }

        # Charger la cle
        collection_documents = self.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_CLES_NOM)
        hint = [(ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES, 1)]
        curseur = collection_documents.find(filtre, hint=hint)

        cles = dict()
        for document_cle in curseur:
            hachage_bytes = document_cle[ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES]

            if domaines_permis is not None:
                # Verifier que la cle correspond a un domaine permis
                if document_cle[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE] not in domaines_permis:
                    self._logger.debug("Le dechiffrage ne permet pas d'acceder au domaine "
                                       "%s" % document_cle[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE])
                    return {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_REFUSE}

            cle_secrete = self.decrypter_cle(document_cle['cles'])
            if cle_secrete is None:
                self._logger.debug("Cle non dechiffrable : "
                                   "%s" % str(evenement))
                return {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_CLE_INDECHIFFRABLE}
            cle_secrete_reencryptee, fingerprint = self.crypter_cle(cle_secrete, enveloppe_rechiffrage.certificat)

            cles[hachage_bytes] = {
                Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_PERMIS,
                'cle': multibase.encode('base64', cle_secrete_reencryptee).decode('utf-8'),
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV: document_cle[
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG: document_cle[
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT: document_cle[
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: document_cle[
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS],
                Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: document_cle[
                    Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE],
            }

        if len(cles) == 0:
            self._logger.debug("Le dechiffrage n'a pas trouve de cle correspondant a : "
                               "%s" % evenement[ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES])
            cle_fournie = evenement.get('cle')
            if cle_fournie and len(evenement[ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES]) == 1:
                domaine = evenement[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
                hachage_bytes = evenement[ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES][0]
                iv = evenement[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV]
                tag = evenement[ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG]
                format_chiffrage = evenement[ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT]
                self._logger.info("On insere la cle dans le maitre des cles pour permettre un "
                                  "rechiffrage subsequent de la cle %s, %s" % (domaine, hachage_bytes))

                fingerprint_millegrille = self.configuration.certificat_millegrille.fingerprint

                information_cle = {
                    Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: domaine,
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                        'adhoc': True,
                    },
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: hachage_bytes,
                    "cles": {
                        fingerprint_millegrille: cle_fournie,
                    },
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV: iv,
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG: tag,
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT: format_chiffrage,
                }

                self.sauvegarder_cle(information_cle)

            return {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_CLE_INCONNUE}

        cles_trouvees = cles.keys()
        for h in evenement[ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES]:
            if h not in cles_trouvees:
                self._logger.debug("Le dechiffrage n'a pas trouve de cle correspondant a : %s" % h)
                cles[h] = {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_CLE_INCONNUE}

        return {
            'cles': cles,
            Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_PERMIS
        }

    def extraire_certificat(self, evenement):
        # Enlever le certificat inclus pour utiliser celui de l'entete (demande permission originale)
        copie_evenement = evenement.copy()
        try:
            del copie_evenement['_certificat']
        except KeyError:
            pass
        # return self.verificateur_transaction.verifier(evenement)
        enveloppe_certificat = self.validateur_message.verifier(evenement)
        return enveloppe_certificat

    def compter_cles_non_dechiffrables(self, message_dict: dict):
        """
        Recupere une batch de cles qui ne sont pas dechiffrables par le maitre des cles.
        Transmet cettre batch pour qu'elle soit dechiffree et retournee sous forme de transactions.
        :param message_dict: taille/int, cle_dechiffrage/str_base64
        :return:
        """
        fingerprint_b64_dechiffrage = message_dict.get('fingerprint_b64_dechiffrage')

        # Fingerprints qui doivent exister pour considerer dechiffrable
        fingerprint_b64_actifs = message_dict.get('fingerprints_actifs') or []
        # Ajouter fingerprint du maitre des cles local
        fingerprint_b64_local = self._contexte.signateur_transactions.enveloppe_certificat_courant.fingerprint
        if fingerprint_b64_local not in fingerprint_b64_actifs:
            fingerprint_b64_actifs.append(fingerprint_b64_local)

        condition_actif = [
            {'non_dechiffrable': True}
        ]
        for fp in fingerprint_b64_actifs:
            fp_avec_fonction = fp
            condition_actif.append({'cles.%s' % fp_avec_fonction: {'$exists': False}})

        if not fingerprint_b64_dechiffrage:
            # Par defaut, assumer que la cle de dechiffrage sera la cle de millegrille
            fingerprint_b64_dechiffrage = self.certificat_millegrille.fingerprint

        collection = self._contexte._document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_CLES_NOM)
        filtre = {
            '$or': condition_actif,
            'cles.' + fingerprint_b64_dechiffrage: {'$exists': True},
            'domaine': {'$ne': None},
        }
        compte = collection.count(filtre)
        reponse = {
            'compte': compte,
        }

        return reponse

    def transmettre_cles_non_dechiffrables(self, message_dict: dict, toutes_cles=False):
        """
        Recupere une batch de cles qui ne sont pas dechiffrables par le maitre des cles.
        Transmet cettre batch pour qu'elle soit dechiffree et retournee sous forme de transactions.
        :param message_dict: taille/int, cle_dechiffrage/str_base64
        :return:
        """
        taille_bacth = message_dict.get('taille') or 1000
        fingerprint_b64_dechiffrage = message_dict.get('fingerprint_b64_dechiffrage')
        hachages_ignorer = message_dict.get('hachage_ignorer')  # Hachage a ignorer (erreur, en cours, etc.)

        # Fingerprints qui doivent exister pour considerer dechiffrable
        fingerprint_b64_actifs = message_dict.get('fingerprints_actifs') or []
        # Ajouter fingerprint du maitre des cles local
        # fingerprint_b64_local = self.verificateur_certificats.enveloppe_certificat_courant.fingerprint_b64
        enveloppe_certificat_courant = self._contexte.signateur_transactions.enveloppe_certificat_courant
        fingerprint_b64_local = enveloppe_certificat_courant.fingerprint
        if fingerprint_b64_local not in fingerprint_b64_actifs:
            fingerprint_b64_actifs.append(fingerprint_b64_local)

        condition_actif = list()

        for fp in fingerprint_b64_actifs:
            condition_actif.append({'cles.%s' % fp: {'$exists': False}})

        if not fingerprint_b64_dechiffrage:
            # Par defaut, assumer que la cle de dechiffrage sera la cle de millegrille
            fingerprint_b64_dechiffrage = self.certificat_millegrille.fingerprint

        collection = self._contexte.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_CLES_NOM)
        filtre = {
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_NON_DECHIFFRABLE: True,
            '$or': condition_actif,
            'cles.' + fingerprint_b64_dechiffrage: {'$exists': True},
            'domaine': {'$ne': None},
        }
        if hachages_ignorer is not None:
            filtre['hachage_bytes'] = {'$nin': hachages_ignorer}

        hint = [
            (ConstantesMaitreDesCles.TRANSACTION_CHAMP_NON_DECHIFFRABLE, 1),
            (Constantes.DOCUMENT_INFODOC_DATE_CREATION, 1),
        ]

        champs = [
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT,
        ]

        resultats = collection.find(filtre).sort(hint).hint(hint).limit(taille_bacth)

        cles = list()
        for doc in resultats:
            cles_existantes = doc.get('cles')
            if cles_existantes is None:
                continue

            # Extraire cle specifique pour rechiffrage
            cle_secrete = cles_existantes.get(fingerprint_b64_dechiffrage)

            if cle_secrete is not None:
                info_cle = {
                    'cle': cle_secrete,
                    # 'domaine_transaction': domaine_transaction,
                }

                if toutes_cles:
                    info_cle['cles'] = cles_existantes

                for champ in champs:
                    valeur = doc.get(champ)
                    if valeur is not None:
                        info_cle[champ] = valeur

                cles.append(info_cle)

        pems = [enveloppe_certificat_courant.certificat_pem]
        pems.extend(enveloppe_certificat_courant.reste_chaine_pem)

        reponse = {
            'cles': cles,
            'certificat_rechiffrage': pems,
        }

        return reponse

    def rechiffrer_cles_apres_rotation(self):
        """
        Tenter de rechiffrer les cles qui n'ont pas encore ete rechiffrees avec le certificat courant.
        :return:
        """

        # Flagger toutes les cles qui ne sont pas supportees par la cle locale (meme si au moins un maitre des cles
        # different est capable de la dechiffrer)
        enveloppe_certificat_courant = self._contexte.signateur_transactions.enveloppe_certificat_courant
        fingerprint = enveloppe_certificat_courant.fingerprint
        collection = self._contexte.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_CLES_NOM)
        filtre = {
            'cles.' + fingerprint: {'$exists': False},
        }
        ops = {
            '$set': {ConstantesMaitreDesCles.TRANSACTION_CHAMP_NON_DECHIFFRABLE: True},
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        resultat_non_dechiffrable = collection.update_many(filtre, ops)
        compte_cles_non_dechiffrables = resultat_non_dechiffrable.matched_count
        if compte_cles_non_dechiffrables == 0:
            # Rien a faire, toutes les cles sont dechiffrables
            return

        info_non_dechiffrables = self.transmettre_cles_non_dechiffrables(dict(), toutes_cles=True)
        cles_non_dechiffrables = info_non_dechiffrables.get('cles')
        compte_cles_non_dechiffrables = 0
        for r in cles_non_dechiffrables:
            self._logger.debug("Cle non dechiffrable : %s" % r)
            # Tenter de dechiffrer la cle symetrique avec une des vieilles cles asymetriques de maitre des cles
            cles_dict = r['cles']
            dechiffree = False
            for cle_sym_b64 in cles_dict.values():
                for clecert in self.__clecert_historique:
                    cle_sym = multibase.decode(cle_sym_b64)
                    try:
                        cle_dechiffree = clecert.dechiffrage_asymmetrique(cle_sym)
                        # Transmettre commande sauvegarder cle
                        self.creer_commande_cles_manquantes(r, cle_dechiffree=cle_dechiffree)
                        self._logger.debug("Cle trouvee pour dechiffrer une cle symmetrique")
                        dechiffree = True
                        break
                    except ValueError:
                        pass  # OK, on fait l'aggregation des echecs a la fin
                    except Exception:
                        self._logger.exception("Erreur dechiffrage")

            if dechiffree is False:
                self._logger.warning("Cle non dechiffrable : %s" % r['hachage_bytes'])
                compte_cles_non_dechiffrables = compte_cles_non_dechiffrables + 1

        if compte_cles_non_dechiffrables > 0:
            self._logger.warning("Rechiffrage : %d cles non dechiffrables" % compte_cles_non_dechiffrables)

    # def signer_cle_backup(self, properties, message_dict):
    #     self._logger.debug("Signer cle de backup : %s" % str(message_dict))
    #
    #     # Verifier que le demandeur a l'autorisation de se faire transmettre la cle racine
    #     en_tete = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
    #     fingerprint_demandeur = en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT]
    #     certificat_demandeur = self._contexte.verificateur_certificats.charger_certificat(fingerprint=fingerprint_demandeur)
    #     exchanges_certificat = certificat_demandeur.get_exchanges
    #     roles_certificat = certificat_demandeur.get_roles
    #
    #     exchanges_acceptes = [ConstantesSecurite.EXCHANGE_PROTEGE, ConstantesSecurite.EXCHANGE_SECURE]
    #     roles_acceptes = [
    #         ConstantesGenerateurCertificat.ROLE_MAITREDESCLES,
    #         ConstantesGenerateurCertificat.ROLE_COUPDOEIL_NAVIGATEUR,
    #         ConstantesGenerateurCertificat.ROLE_COUPDOEIL
    #     ]
    #     if not any(exchange in exchanges_acceptes for exchange in exchanges_certificat):
    #         raise Exception("Certificat %s non autorise a recevoir cle racine (exchange)" % fingerprint_demandeur)
    #     if not any(exchange in roles_acceptes for exchange in roles_certificat):
    #         raise Exception("Certificat %s non autorise a recevoir cle racine (role)" % fingerprint_demandeur)
    #
    #     public_key_str = message_dict['cle_publique']
    #     if 'BEGIN PUBLIC KEY' not in public_key_str:
    #         public_key_str = PemHelpers.wrap_public_key(public_key_str)
    #     sujet = 'Backup'
    #
    #     # Trouver generateur pour le role
    #     renouvelleur = self.renouvelleur_certificat
    #     clecert = renouvelleur.signer_backup(public_key_str, sujet)
    #
    #     # Generer nouvelle transaction pour sauvegarder le certificat
    #     transaction = {
    #         ConstantesPki.LIBELLE_CERTIFICAT_PEM: clecert.cert_bytes.decode('utf-8'),
    #         ConstantesPki.LIBELLE_FINGERPRINT: clecert.fingerprint,
    #         ConstantesPki.LIBELLE_SUBJECT: clecert.formatter_subject(),
    #         ConstantesPki.LIBELLE_NOT_VALID_BEFORE: int(clecert.not_valid_before.timestamp()),
    #         ConstantesPki.LIBELLE_NOT_VALID_AFTER: int(clecert.not_valid_after.timestamp()),
    #         ConstantesPki.LIBELLE_SUBJECT_KEY: clecert.skid,
    #         ConstantesPki.LIBELLE_AUTHORITY_KEY: clecert.akid,
    #         ConstantesPki.LIBELLE_ROLES: clecert.get_roles
    #     }
    #
    #     self.generateur_transactions.soumettre_transaction(
    #         transaction,
    #         ConstantesPki.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT
    #     )
    #
    #     # Ajouter certificat a la liste des certs de backup
    #     enveloppe = EnveloppeCertificat(certificat_pem=clecert.cert_bytes)
    #     fingerprint_backup = EnveloppeCertificat.calculer_fingerprint_b64(enveloppe.certificat)
    #     self.__certificats_backup[fingerprint_backup] = enveloppe
    #
    #     # Rechiffrer toutes les cles avec ce nouveau certificat de backup
    #     processus = "millegrilles_domaines_MaitreDesCles:ProcessusTrouverClesBackupManquantes"
    #     fingerprints_backup = {'fingerprints_base64': list(self.__certificats_backup.keys())}
    #     self.demarrer_processus(processus, fingerprints_backup)
    #
    #     # Creer une reponse pour coupdoeil
    #     info_cert = transaction.copy()
    #     del info_cert[ConstantesPki.LIBELLE_CERTIFICAT_PEM]
    #
    #     return {
    #         'certificat_info': info_cert,
    #         'cert': clecert.cert_bytes.decode('utf-8'),
    #         'fullchain': clecert.chaine,
    #     }

    def sauvegarder_cle(self, message_dict: dict, properties=None):
        """
        Sauvegarder une cle. Genere les transactions manquantes au besoin.
        :param message_dict:
        :return:
        """
        filtre = {
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: message_dict[
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES],
        }

        collection_cles = self.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_CLES_NOM)
        document_existant_cle = collection_cles.find_one(filtre)

        fingerprints_inconnus = message_dict['cles'].keys()
        flag_non_dechiffrable = False
        if document_existant_cle is not None:
            # Le document existe deja pour cette cle - on verifie s'il nous manque des fingerprint
            fingerprint_connus = document_existant_cle['cles'].keys()
            flag_non_dechiffrable = document_existant_cle[ConstantesMaitreDesCles.TRANSACTION_CHAMP_NON_DECHIFFRABLE]

            for fp in fingerprint_connus:
                try:
                    del message_dict['cles'][fp]
                except KeyError:
                    pass  #OK

        # Creer une transaction pour sauvegarder chaque fingerprint inconnu
        for fp in fingerprints_inconnus:
            cle = message_dict['cles'][fp]

            transaction = {
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_FINGERPRINT: fp,
                Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: message_dict[
                    Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: message_dict[
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV: message_dict[
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG: message_dict[
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT: message_dict[
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: message_dict[
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_CLE_INDIVIDUELLE: cle,
            }

            # Creer domaine action (ex. MaitreDesCles.d16034660842cc9ad9ef37735069f3e3b534f728.cle)
            domaine_action_transaction = '.'.join([
                ConstantesMaitreDesCles.DOMAINE_NOM,
                fp,  # Sous-domaine est le fingerprint du certificat
                ConstantesMaitreDesCles.TRANSACTION_CLE,
            ])

            reply_to = None
            correlation_id = None
            if properties is not None:
                reply_to = properties.reply_to
                correlation_id = properties.correlation_id

            # Soumettre transaction - utiliser reply_to et correlation de l'appeleur
            # Va faire transmettre la confirmation de transactions a l'appeleur
            self.generateur_transactions.soumettre_transaction(
                transaction, domaine_action_transaction,
                reply_to=reply_to, correlation_id=correlation_id
            )

        if len(fingerprints_inconnus) == 0:
            # Aucune transaction a creer, on retourne la reponse
            return {'ok': True}

    def get_nom_queue(self):
        return ConstantesMaitreDesCles.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesMaitreDesCles.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesMaitreDesCles.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesMaitreDesCles.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesMaitreDesCles.DOMAINE_NOM

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes

    def get_handler_commandes(self) -> dict:
        return self.__handler_commandes

    @property
    def get_certificat(self):
        return self._contexte.signateur_transactions.enveloppe_certificat_courant.certificat

    @property
    def get_certificat_pem(self):
        return self._contexte.signateur_transactions.enveloppe_certificat_courant.certificat_pem

    @property
    def get_chaine_pem(self):
        return self._contexte.signateur_transactions.enveloppe_certificat_courant.chaine_pem()

    @property
    def get_ca_pem(self):
        return self.__ca_file_pem

    @property
    def get_certificats_backup(self):
        return self.__certificats_backup

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

    @property
    def version_domaine(self):
        return ConstantesMaitreDesCles.TRANSACTION_VERSION_COURANTE

    @property
    def renouvelleur_certificat(self) -> RenouvelleurCertificat:
        return self.__renouvelleur_certificat

    def creer_commande_cles_manquantes(self, document, clecert_dechiffrage: EnveloppeCleCert = None, cle_dechiffree: bytes = None):
        """
        Methode qui va dechiffrer une cle secrete et la rechiffrer pour chaque cle backup/maitre des cles manquant.

        :param clecert_dechiffrage: Clecert qui peut dechiffrer toutes les cles chiffrees.
        :param document: Document avec des cles chiffrees manquantes.
        :return:
        """

        # Recuperer liste des certs a inclure
        enveloppe_maitredescles = self._contexte.signateur_transactions.enveloppe_certificat_courant
        clecert_maitredescles = EnveloppeCleCert(cert=enveloppe_maitredescles.certificat)
        dict_certs = self.get_certificats_backup.copy()
        dict_certs[clecert_maitredescles.fingerprint] = clecert_maitredescles
        cles_connues = [c for c in list(dict_certs.keys())]
        cles_documents = list(document[ConstantesMaitreDesCles.TRANSACTION_CHAMP_CLES].keys())

        # Parcourir
        cle_deja_dechiffrable = True
        for fingerprint in cles_connues:
            if fingerprint not in cles_documents:
                cle_deja_dechiffrable = False
                identificateur_document = document[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS]

                self._logger.debug("Ajouter cle %s dans document %s" % (
                    fingerprint, identificateur_document))
                enveloppe_backup = dict_certs[fingerprint]

                try:
                    # Type EnveloppeCertificat
                    certificat = enveloppe_backup.certificat
                except AttributeError:
                    # Type EnveloppeCleCert
                    certificat = enveloppe_backup.cert

                cle_chiffree_backup, fingerprint = self.crypter_cle(cle_dechiffree, cert=certificat)
                cle_chiffree_backup = multibase.encode('base64', cle_chiffree_backup).decode('utf-8')
                self._logger.debug("Cle re-chiffree pour cert %s" % fingerprint)

                commande = {
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_CLES: {
                        fingerprint: cle_chiffree_backup,
                    },
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_DOMAINE: document[
                        ConstantesMaitreDesCles.TRANSACTION_CHAMP_DOMAINE],
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV: document[
                        ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV],
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG: document[
                        ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG],
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT: document[
                        ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT],
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: identificateur_document,
                    ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: document[
                        ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES],
                }
                if document.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID):
                    commande[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID] = document[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

                domaine_action = '.'.join(['commande', ConstantesMaitreDesCles.DOMAINE_NOM, ConstantesMaitreDesCles.COMMANDE_SAUVEGARDER_CLE])

                # Soumettre la commande immediatement
                self.generateur_transactions.transmettre_commande(commande, domaine_action)

        if cle_deja_dechiffrable:
            # On a un flag non-dechiffrable pour une cle qui est deja dechiffrable
            # Mettre a jour le document immediatement
            collection_cles = self.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_CLES_NOM)
            filtre = {
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: document[ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES]
            }
            ops = {
                '$set': {ConstantesMaitreDesCles.TRANSACTION_CHAMP_NON_DECHIFFRABLE: False},
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
            }
            collection_cles.update_one(filtre, ops)

    # def creer_transaction_motsdepasse_manquants(self, document, clecert_dechiffrage: EnveloppeCleCert = None):
    #     """
    #     Methode qui va dechiffrer un mot de passe et le rechiffrer pour chaque cle backup/maitre des cles manquant.
    #
    #     :param clecert_dechiffrage: Clecert qui peut dechiffrer toutes les cles chiffrees.
    #     :param document: Document avec des cles chiffrees manquantes.
    #     :return:
    #     """
    #
    #     # Extraire cle secrete en utilisant le certificat du maitre des cles courant
    #     try:
    #
    #         if clecert_dechiffrage:
    #             fingerprint_cert_dechiffrage = clecert_dechiffrage.fingerprint_b64
    #             cle_chiffree = document[ConstantesMaitreDesCles.TRANSACTION_CHAMP_MOTDEPASSE][
    #                 fingerprint_cert_dechiffrage]
    #             cle_dechiffree = clecert_dechiffrage.dechiffrage_asymmetrique(cle_chiffree)
    #         else:
    #             # Par defaut, utiliser clecert du maitredescles
    #             cle_dechiffree = self.decrypter_motdepasse(document)
    #
    #     except KeyError:
    #         self._logger.exception("Cle du document non-rechiffrable (%s), cle secrete associe au cert introuvable" %
    #                                document.get(ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS))
    #         return
    #
    #     # Recuperer liste des certs a inclure
    #     enveloppe_maitredescles = self._contexte.signateur_transactions.enveloppe_certificat_courant
    #     clecert_maitredescles = EnveloppeCleCert(cert=enveloppe_maitredescles.certificat)
    #
    #     dict_certs = self.get_certificats_backup.copy()
    #     dict_certs[clecert_maitredescles.fingerprint_b64] = clecert_maitredescles
    #     cles_connues = list(dict_certs.keys())
    #     cles_documents = list(document[ConstantesMaitreDesCles.TRANSACTION_CHAMP_MOTDEPASSE].keys())
    #
    #     # Parcourir
    #     for fingerprint in cles_connues:
    #         if fingerprint not in cles_documents:
    #             identificateur_document = document[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS]
    #
    #             self._logger.debug("Ajouter cle %s dans document %s" % (
    #                 fingerprint, identificateur_document))
    #             enveloppe_backup = dict_certs[fingerprint]
    #             fingerprint_backup_b64 = enveloppe_backup.fingerprint_b64
    #
    #             try:
    #                 # Type EnveloppeCertificat
    #                 certificat = enveloppe_backup.certificat
    #             except AttributeError:
    #                 # Type EnveloppeCleCert
    #                 certificat = enveloppe_backup.cert
    #
    #             cle_chiffree_backup, fingerprint_hex = self.crypter_cle(cle_dechiffree, cert=certificat)
    #             cle_chiffree_backup_base64 = str(b64encode(cle_chiffree_backup), 'utf-8')
    #             self._logger.debug("Cle chiffree pour cert %s : %s" % (fingerprint_backup_b64, cle_chiffree_backup_base64))
    #
    #             transaction = {
    #                 ConstantesMaitreDesCles.TRANSACTION_CHAMP_SUJET_CLE: document[Constantes.DOCUMENT_INFODOC_LIBELLE],
    #                 ConstantesMaitreDesCles.TRANSACTION_CHAMP_MOTDEPASSE: {
    #                     fingerprint_backup_b64: cle_chiffree_backup_base64
    #                 },
    #
    #                 ConstantesMaitreDesCles.TRANSACTION_CHAMP_DOMAINE: document[ConstantesMaitreDesCles.TRANSACTION_CHAMP_DOMAINE],
    #                 ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: identificateur_document,
    #                 Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: document[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
    #             }
    #             sujet = document.get(ConstantesMaitreDesCles.TRANSACTION_CHAMP_SUJET_CLE)
    #             if sujet:
    #                 transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_SUJET_CLE] = sujet
    #
    #             # Soumettre la transaction immediatement
    #             # Permet de fonctionner incrementalement si le nombre de cles est tres grand
    #             self.generateur_transactions.soumettre_transaction(
    #                 transaction,
    #                 ConstantesMaitreDesCles.TRANSACTION_MAJ_MOTDEPASSE,
    #                 version=ConstantesMaitreDesCles.TRANSACTION_VERSION_COURANTE,
    #             )

    def transmettre_certificat(self, properties):
        """
        Transmet le certificat courant du MaitreDesCles au demandeur.
        :param properties:
        :return:
        """
        self._logger.debug("Transmettre certificat a %s" % properties.reply_to)
        # Genere message reponse
        message_resultat = {
            'certificat_millegrille': self.get_ca_pem,
            'certificat': self.get_chaine_pem,
            'certificats_backup': self.get_certificats_backup,
        }

        self.generateur_transactions.transmettre_reponse(
            message_resultat, properties.reply_to, properties.correlation_id
        )

    def maj_document_cle(self, transaction: dict, non_dechiffrable=None):

        contenu_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesCles.DOCUMENT_LIBVAL_CLE,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV: transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV],
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG: transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG],
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT: transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT],
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: transaction[
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES],
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: transaction[
                Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        }

        version_courante = transaction.get(ConstantesMaitreDesCles.TRANSACTION_CHAMP_UUID_ORIGINAL) or \
                           transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                               Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        set_ops = {
            'version_courante': version_courante,
        }

        identificateurs_documents = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS]
        # Extraire les cles de document de la transaction (par processus d'elimination)
        for champ, valeur in identificateurs_documents.items():
            try:
                nom_champ = '.'.join([ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS, champ])
                set_ops[nom_champ] = identificateurs_documents[champ]
            except KeyError:
                pass

        if non_dechiffrable is not None:
            set_ops['non_dechiffrable'] = non_dechiffrable
        else:
            contenu_on_insert['non_dechiffrable'] = True

        hachage_sha256 = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_FINGERPRINT]

        champ_cles = '.'.join([
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_CLES,
            hachage_sha256
        ])
        set_ops[champ_cles] = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_CLE_INDIVIDUELLE]

        operations_mongo = {
            '$set': set_ops,
            '$setOnInsert': contenu_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        filtre = {
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: transaction[
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES]
        }

        collection_documents = self.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_CLES_NOM)
        self._logger.debug("Operations: %s" % str({'filtre': filtre, 'operation': operations_mongo}))

        resultat_update = collection_documents.update_one(filter=filtre, update=operations_mongo, upsert=True)
        if resultat_update.upserted_id is not None:
            self._logger.debug("_id du document MaitreDesCles: %s" % str(resultat_update.upserted_id))
        if resultat_update.upserted_id is None and resultat_update.matched_count != 1:
            raise Exception("Erreur insertion cles")

    @property
    def certificat_millegrille(self) -> EnveloppeCertificat:
        return self.__certificat_millegrille

    @property
    def supporte_regenerer_global(self):
        """
        :return: False, le maitre de cles ne supporte pas regeneration globale
        """
        return False

    @property
    def handler_backup(self):
        return self.__handler_backup

    @property
    def get_collections_documents(self):
        return [
            ConstantesMaitreDesCles.COLLECTION_DOCUMENTS_NOM,
            ConstantesMaitreDesCles.COLLECTION_CLES_NOM,
        ]


class HandlerBackupMaitreDesCles(HandlerBackupDomaine):

    def __init__(self, contexte):
        super().__init__(contexte,
                         ConstantesMaitreDesCles.DOMAINE_NOM,
                         ConstantesMaitreDesCles.COLLECTION_TRANSACTIONS_NOM,
                         ConstantesMaitreDesCles.COLLECTION_DOCUMENTS_NOM)

    def _doit_chiffrer(self):
        """
        Les transactions de cles sont deja chiffrees (asymetrique). On ne rechiffre pas une deuxieme fois.
        :return:
        """
        return False


class ProcessusReceptionCles(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    # def traitement_regenerer(self, id_transaction, parametres_processus):
    #     """ Aucun traitement necessaire, le resultat est re-sauvegarde sous une nouvelle transaction """
    #     pass

    def recrypterCle(self, cle_symmetrique_chiffree):
        # cert_maitredescles = self._controleur.gestionnaire.get_certificat
        # fingerprint_certmaitredescles = b64encode(cert_maitredescles.fingerprint(hashes.SHA1())).decode('utf-8')
        # cle_symmetrique_chiffree = cle_secrete_encryptee['cle']
        # cles_secretes_encryptees = cle_secrete_encryptee.copy()

        cle_secrete = self._controleur.gestionnaire.decrypter_contenu(cle_symmetrique_chiffree)
        # self._logger.debug("Cle secrete: %s" % cle_secrete)

        # Re-encrypter la cle secrete avec les cles backup
        cert_rechiffrage = [self.controleur.gestionnaire.certificat_millegrille]
        cert_rechiffrage.extend(self._controleur.gestionnaire.get_certificats_backup.values())
        cles_secretes_encryptees = dict()
        for backup in cert_rechiffrage:
            cle_secrete_backup, fingerprint = self.controleur.gestionnaire.crypter_cle(cle_secrete, cert=backup.certificat)
            # fingerprint_b64 = b64encode(binascii.unhexlify(fingerprint)).decode('utf-8')
            cles_secretes_encryptees[fingerprint] = multibase.encode('base64', cle_secrete_backup).decode('utf-8')

        return cles_secretes_encryptees

    def generer_transactions_backup(self, sujet, domaine=None):
        """
        Genere les transaction manquantes pour cle de millegrille ou cles de backup
        Remplace le domaine MaitreDesCles.* par MaitreDesCles.FINGERPRINTB64.*
        :param sujet:
        :return:
        """
        transaction = self.transaction
        domaine_action = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        action = domaine_action.split('.')[-1]

        cert_millegrille = self.controleur.gestionnaire.certificat_millegrille
        fingerprint_cert_millegrille = cert_millegrille.fingerprint_b64

        fingerprint_backup = [fingerprint_cert_millegrille]
        if self._controleur.gestionnaire.get_certificats_backup is not None:
            certificats_backup = self.controleur.gestionnaire.get_certificats_backup
            for fingerprint_cle_backup in certificats_backup.keys():
                fingerprint_backup.append(fingerprint_cle_backup)

        for fingerprint, cle in self.parametres['cles_rechiffrees'].items():
            if fingerprint not in fingerprint_backup:
                continue

            # Convertir fingerprint b64 en hex - safe pour routing key MQ et nom de fichier
            sous_domaine = '.'.join([ConstantesMaitreDesCles.DOMAINE_NOM, fingerprint, action + 'Backup'])
            domaine_effectif = domaine or transaction.get('domaine')

            transaction_cle = {
                'domaine': domaine_effectif,
                'identificateurs_document': transaction['identificateurs_document'],
                Constantes.ConstantesSecurityPki.LIBELLE_FINGERPRINT: fingerprint,
                'cle': cle,
                'iv': transaction['iv'],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_UUID_ORIGINAL: transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
            }

            self.ajouter_transaction_a_soumettre(sous_domaine, transaction_cle)

    def mettre_a_jour_document(self, transaction):
        # Decrypter la cle secrete et la re-encrypter avec toutes les cles backup
        cle_recue = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_CLE_INDIVIDUELLE]
        identificateurs_document = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS]
        hachage_bytes = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES]
        nouveaux_params = {
            # ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: identificateurs_document,
            'cle_recue': cle_recue,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV: transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV],
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG: transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG],
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT: transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_FORMAT],
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: hachage_bytes,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE],
        }

        non_dechiffrable = None
        try:
            cles_rechiffrees = self.recrypterCle(cle_recue)
            non_dechiffrable = False  # Aucune erreur d'extraction, la cle est lisible
            nouveaux_params['cles_rechiffrees'] = cles_rechiffrees
        except ValueError:
            pass  # Confirmation - cle non dechiffrable avec cle recue

        nouveaux_params['cle_non_dechiffrable'] = non_dechiffrable
        self.controleur.gestionnaire.maj_document_cle(transaction, non_dechiffrable=non_dechiffrable)

        return nouveaux_params


class ProcessusNouvelleCle(ProcessusReceptionCles):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    # def traitement_regenerer(self, id_transaction, parametres_processus):
    #     """ Aucun traitement necessaire, le resultat est re-sauvegarde sous une nouvelle transaction """
    #     pass

    def initiale(self):
        transaction = self.transaction

        nouveaux_params = self.mettre_a_jour_document(transaction)

        self.set_etape_suivante()  # Termine

        return nouveaux_params


class ProcessusTrouverClesBackupManquantes(MGProcessus):
    """
    Processus qui identifie les documents de MaitreDesCles avec des cles manquantes.
    Utilise la liste des fingerprints en parametres comme selecteur, mais rechiffre avec
    toutes les cles backup/maitre des cles actives.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        fingerprints = self.parametres['fingerprints_base64']

        erreurs = list()
        for doc in self.curseur_docs_cle_manquante(fingerprints):
            self.__logger.debug("Cles manquantes dans " + str(doc))
            self.controleur.gestionnaire.creer_commande_cles_manquantes(doc)

        self.set_etape_suivante()  # Termine

        return {'erreurs': erreurs}

    def curseur_docs_cle_manquante(self, fingerprints):
        liste_operateurs = list()
        for fingerprint_base64 in fingerprints:
            liste_operateurs.append({'cles.%s' % fingerprint_base64: {'$exists': False}})
        # Extraire la liste de cles qui n'ont pas tous ces certificats
        filtre = {
            '$or': liste_operateurs
        }

        collection_documents = self.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_CLES_NOM)
        return collection_documents.find(filtre)


class CleNonDechiffrableException(Exception):
    pass
