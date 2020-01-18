# Domaine MaitreDesCles
# Responsable de la gestion et de l'acces aux cles secretes pour les niveaux 3.Protege et 4.Secure.

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMaitreDesCles
from millegrilles.Domaines import GestionnaireDomaineStandard, TransactionTypeInconnuError
from millegrilles.domaines.GrosFichiers import ConstantesGrosFichiers
from millegrilles.dao.MessageDAO import TraitementMessageDomaine, CertificatInconnu
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.util.X509Certificate import EnveloppeCleCert, GenererMaitredesclesCryptage, \
    ConstantesGenerateurCertificat, RenouvelleurCertificat, PemHelpers
from millegrilles.util.JSONEncoders import DocElemFilter
from millegrilles.domaines.Pki import ConstantesPki
from millegrilles.domaines.Annuaire import ConstantesAnnuaire

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from base64 import b64encode, b64decode

import logging
import datetime
import json
import socket


class GestionnaireMaitreDesCles(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self.__repertoire_maitredescles = self.configuration.pki_config[Constantes.CONFIG_MAITREDESCLES_DIR]

        self.__nomfichier_maitredescles_cert = self.configuration.pki_config[Constantes.CONFIG_PKI_CERT_MAITREDESCLES]
        self.__nomfichier_autorite_cert = self.configuration.pki_config[Constantes.CONFIG_PKI_CERT_AUTORITE]
        self.__nomfichier_maitredescles_key = self.configuration.pki_config[Constantes.CONFIG_PKI_KEY_MAITREDESCLES]
        self.__nomfichier_maitredescles_password = self.configuration.pki_config[Constantes.CONFIG_PKI_PASSWORD_MAITREDESCLES]
        self.__clecert_millegrille = None  # Cle et certificat de millegrille
        self.__clecert_maitredescles = None  # Cle et certificat de maitredescles local
        self.__certificat_courant_pem = None
        self.__certificat_intermediaires_pem = None
        self.__certificats_backup = None  # Liste de certificats backup utilises pour conserver les cles secretes.
        self.__dict_ca = None  # Key=akid, Value=x509.Certificate()

        self.__renouvelleur_certificat = None

        # Queue message handlers
        self.__handler_requetes_noeuds = None

    def configurer(self):
        super().configurer()

        self.__handler_requetes_noeuds = TraitementRequetesNoeuds(self)

        self.charger_ca_chaine()
        self.__clecert_millegrille = self.charger_clecert_millegrille()

        self.__renouvelleur_certificat = RenouvelleurCertificat(
            self.configuration.idmg,
            self.__dict_ca,
            self.__clecert_millegrille
        )

        try:
            self.charger_certificat_courant()
        except FileNotFoundError as fnf:
            self._logger.warning("Certificat maitredescles non trouve, on va en generer un nouveau. %s" % str(fnf))
            self.creer_certificat_maitredescles()

        self.charger_certificats_backup()

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

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesMaitreDesCles.LIBVAL_CONFIGURATION, ConstantesMaitreDesCles.DOCUMENT_DEFAUT)

    def charger_ca_chaine(self):
        self.__dict_ca = dict()

        self._logger.info("CA FILE: %s" % self.configuration.pki_cafile)
        ca_file = self.configuration.pki_cafile
        with open(ca_file, 'rb') as fichier:
            cert = fichier.read()
            x509_cert = x509.load_pem_x509_certificate(cert, backend=default_backend())
            skid = EnveloppeCleCert.get_subject_identifier(x509_cert)
            self.__dict_ca[skid] = x509_cert

        self._logger.info("Cert maitre des cles: %s" % self.configuration.pki_certfile)
        with open(self.configuration.pki_certfile, 'r') as fichier:
            chaine = fichier.read()
            chaine = PemHelpers.split_certificats(chaine)

            # Prendre tous les certificats apres le premier (c'est celui du maitre des cles)
            for cert in chaine[1:]:
                x509_cert = x509.load_pem_x509_certificate(cert.encode('utf-8'), backend=default_backend())
                skid = EnveloppeCleCert.get_subject_identifier(x509_cert)
                self.__dict_ca[skid] = x509_cert

    def charger_clecert_millegrille(self) -> EnveloppeCleCert:
        repertoire_secrets = self.configuration.pki_config[Constantes.CONFIG_PKI_SECRET_DIR]
        passwords_ca = self.configuration.pki_config[Constantes.CONFIG_CA_PASSWORDS]
        with open('%s/%s' % (repertoire_secrets, passwords_ca)) as fichier:
            passwords_ca_dict = json.load(fichier)

        cert_millegrille = '%s/%s' % (repertoire_secrets, self.configuration.pki_config[Constantes.CONFIG_PKI_CERT_MILLEGRILLE])
        key_millegrille = '%s/%s' % (repertoire_secrets, self.configuration.pki_config[Constantes.CONFIG_PKI_KEY_MILLEGRILLE])
        clecert = EnveloppeCleCert()
        clecert.from_files(
            key_millegrille,
            cert_millegrille,
            passwords_ca_dict['pki.ca.millegrille'].encode('utf-8')
        )

        return clecert

    def creer_certificat_maitredescles(self):
        self._logger.info("Generation de nouveau certificat de maitre des cles")
        hostname = socket.gethostname()
        generateurMaitreDesCles = GenererMaitredesclesCryptage(
            self.configuration.idmg,
            ConstantesGenerateurCertificat.ROLE_MAITREDESCLES,
            hostname,
            self.__dict_ca,
            self.__clecert_millegrille
        )
        clecert = generateurMaitreDesCles.generer()

        # repertoire_maitredescles = self.configuration.pki_config[Constantes.CONFIG_MAITREDESCLES_DIR]
        self._logger.debug("Sauvegarde cert maitre des cles: %s/%s" % (self.__repertoire_maitredescles, self.__nomfichier_maitredescles_cert))
        with open('%s/%s' % (self.__repertoire_maitredescles, self.__nomfichier_maitredescles_key), 'wb') as fichier:
            fichier.write(clecert.private_key_bytes)
        with open('%s/%s' % (self.__repertoire_maitredescles, self.__nomfichier_maitredescles_password), 'wb') as fichier:
            fichier.write(clecert.password)
        with open('%s/%s' % (self.__repertoire_maitredescles, self.__nomfichier_maitredescles_cert), 'wb') as fichier:
            fichier.write(clecert.cert_bytes)

        self._logger.info("Nouveau certificat MaitreDesCles genere:\n%s" % (clecert.cert_bytes.decode('utf-8')))

        # Enchainer pour charger le certificat normalement
        self.charger_certificat_courant()

    def charger_certificat_courant(self):
        fichier_cert = '%s/%s' % (self.__repertoire_maitredescles, self.__nomfichier_maitredescles_cert)
        fichier_autorite = '%s/%s' % (self.__repertoire_maitredescles, self.__nomfichier_autorite_cert)
        fichier_cle = '%s/%s' % (self.__repertoire_maitredescles, self.__nomfichier_maitredescles_key)
        mot_de_passe = '%s/%s' % (self.__repertoire_maitredescles, self.__nomfichier_maitredescles_password)

        with open(mot_de_passe, 'rb') as motpasse_courant:
            motpass = motpasse_courant.readline().strip()
        with open(fichier_cle, "rb") as keyfile:
            cle = serialization.load_pem_private_key(
                keyfile.read(),
                password=motpass,
                backend=default_backend()
            )

        with open(fichier_cert, 'rb') as certificat_pem:
            certificat_courant_pem = certificat_pem.read()
            cert = x509.load_pem_x509_certificate(
                certificat_courant_pem,
                backend=default_backend()
            )
            cert_fullchain = certificat_courant_pem.decode('utf8')
            self.__certificat_courant_pem = PemHelpers.split_certificats(cert_fullchain)[0]

        with open(fichier_autorite, 'rb') as fichier:
            certificat_autorite_pem = fichier.read()
            self.__certificat_intermediaires_pem = certificat_autorite_pem.decode('utf8')

        self.__clecert_maitredescles = EnveloppeCleCert(cle, cert, motpass)

        self._logger.info("Certificat courant: %s" % str(cert.subject))

    def charger_certificats_backup(self):
        """
        Charge les certificats de backup presents dans le repertoire des certificats.
        Les cles publiques des backups sont utilisees pour re-encrypter les cles secretes.
        :return:
        """
        certificats_backup = list()

        # Aller chercher les certs dans mongo
        # A FAIRE

        if len(certificats_backup) > 0:
            self.__certificats_backup = certificats_backup

    def identifier_processus(self, domaine_transaction):

        if domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_GROSFICHIER:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCleGrosFichier"
        elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_DOCUMENT:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCleDocument"
        elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_MAJ_DOCUMENT_CLES:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusMAJDocumentCles"
        elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_RENOUVELLEMENT_CERTIFICAT:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusRenouvellerCertificat"
        elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_SIGNER_CERTIFICAT_NOEUD:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusSignerCertificatNoeud"
        elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_GENERER_CERTIFICAT_NAVIGATEUR:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusGenererCertificatNavigateur"
        elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_DECLASSER_CLE_GROSFICHIER:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusDeclasserCleGrosFichier"
        elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_GENERER_DEMANDE_INSCRIPTION:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusGenererDemandeInscription"
        elif domaine_transaction == ConstantesMaitreDesCles.TRANSACTION_GENERER_CERTIFICAT_POUR_TIERS:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusGenererCertificatPourTiers"

        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def decrypter_contenu(self, contenu):
        """
        Utilise la cle privee en memoire pour decrypter le contenu.
        :param contenu:
        :return:
        """
        contenu_bytes = b64decode(contenu)

        contenu_decrypte = self.__clecert_maitredescles.private_key.decrypt(
            contenu_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return contenu_decrypte

    def decrypter_cle(self, dict_cles):
        """
        Decrypte la cle secrete en utilisant la cle prviee d'un certificat charge en memoire
        :param dict_cles: Dictionnaire de cles secretes cryptes, la cle_dict est le fingerprint du certificat
        :return:
        """
        fingerprint_courant = self.get_fingerprint_cert()
        cle_secrete_cryptee = dict_cles.get(fingerprint_courant)
        if cle_secrete_cryptee is not None:
            # On peut decoder la cle secrete
            return self.decrypter_contenu(cle_secrete_cryptee)
        else:
            return None

    def crypter_cle(self, cle_secrete, cert=None):
        if cert is None:
            cert = self.__clecert_maitredescles.cert
        cle_secrete_backup = cert.public_key().encrypt(
            cle_secrete,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        fingerprint = self.get_fingerprint_cert(cert)
        return cle_secrete_backup, fingerprint

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

    def generer_certificat_connecteur(self, idmg_tiers, csr) -> EnveloppeCleCert:
        # Trouver generateur pour le role
        renouvelleur = self.renouvelleur_certificat
        certificat = renouvelleur.signer_connecteur_tiers(idmg_tiers, csr)
        clecert = EnveloppeCleCert(cert=certificat)

        return clecert

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

    def get_handler_requetes_noeuds(self):
        return self.__handler_requetes_noeuds

    @property
    def get_certificat(self):
        return self.__clecert_maitredescles.cert

    @property
    def get_certificat_pem(self):
        return self.__certificat_courant_pem

    @property
    def get_intermediaires_pem(self):
        return self.__certificat_intermediaires_pem

    @property
    def get_certificats_backup(self):
        return self.__certificats_backup

    def get_fingerprint_cert(self, cert=None):
        if cert is None:
            cert = self.get_certificat
        return b64encode(cert.fingerprint(hashes.SHA1())).decode('utf-8')

    def traiter_cedule(self, evenement):
        pass

    @property
    def version_domaine(self):
        return ConstantesMaitreDesCles.TRANSACTION_VERSION_COURANTE

    @property
    def renouvelleur_certificat(self) -> RenouvelleurCertificat:
        return self.__renouvelleur_certificat


class TraitementRequetesNoeuds(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        routing_key_sansprefixe = routing_key.replace(
            'requete.%s.' % ConstantesMaitreDesCles.DOMAINE_NOM,
            ''
        )

        if routing_key_sansprefixe == ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES:
            # Transmettre le certificat courant du maitre des cles
            self.transmettre_certificat(properties)
        elif routing_key_sansprefixe == ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_GROSFICHIER:
            self.transmettre_cle_grosfichier(message_dict, properties)
        elif routing_key_sansprefixe == ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_DOCUMENT:
            self.transmettre_cle_document(message_dict, properties)
        else:
            # Type de transaction inconnue, on lance une exception
            raise TransactionTypeInconnuError("Type de transaction inconnue: message: %s" % message_dict, routing_key)

    def transmettre_certificat(self, properties):
        """
        Transmet le certificat courant du MaitreDesCles au demandeur.
        :param properties:
        :return:
        """
        self._logger.debug("Transmettre certificat a %s" % properties.reply_to)
        # Genere message reponse
        message_resultat = {
            'certificat': self._gestionnaire.get_certificat_pem,
            'certificats_intermediaires': [self._gestionnaire.get_intermediaires_pem],
        }

        self._gestionnaire.generateur_transactions.transmettre_reponse(
            message_resultat, properties.reply_to, properties.correlation_id
        )

    def transmettre_cle_grosfichier(self, evenement, properties):
        """
        Verifie si la requete de cle est valide, puis transmet une reponse (cle re-encryptee ou acces refuse)
        :param evenement:
        :param properties:
        :return:
        """
        self._logger.debug("Transmettre cle grosfichier a %s" % properties.reply_to)

        # Verifier que la signature de la requete est valide - c'est fort probable, il n'est pas possible de
        # se connecter a MQ sans un certificat verifie. Mais s'assurer qu'il n'y ait pas de "relais" via un
        # messager qui a acces aux noeuds. La signature de la requete permet de faire cette verification.
        certificat_demandeur = self.gestionnaire.verificateur_transaction.verifier(evenement)
        enveloppe_certificat = certificat_demandeur

        # Aucune exception lancee, la signature de requete est valide et provient d'un certificat autorise et connu

        # Verifier si on utilise un certificat different pour re-encrypter la cle
        fingerprint_demande = evenement.get('fingerprint')
        if fingerprint_demande is not None:
            self._logger.debug("Re-encryption de la cle secrete avec certificat %s" % fingerprint_demande)
            try:
                enveloppe_certificat = self.gestionnaire.verificateur_certificats.charger_certificat(fingerprint=fingerprint_demande)

                # S'assurer que le certificat est d'un type qui permet d'exporter le contenu
                if ConstantesGenerateurCertificat.ROLE_COUPDOEIL_NAVIGATEUR in enveloppe_certificat.get_roles:
                    pass
                elif ConstantesGenerateurCertificat.ROLE_DOMAINES in certificat_demandeur.get_roles:
                    # Le middleware a le droit de demander une cle pour un autre composant
                    pass
                else:
                    self._logger.warning("Refus decrryptage cle avec fingerprint %s" % fingerprint_demande)
                    enveloppe_certificat = None
            except CertificatInconnu:
                enveloppe_certificat = None

        if enveloppe_certificat is None:
            acces_permis = False
        else:
            self._logger.debug(
                "Verification signature requete cle grosfichier. Cert: %s" % str(
                    enveloppe_certificat.fingerprint_ascii))
            acces_permis = True  # Pour l'instant, les noeuds peuvent tout le temps obtenir l'acces a 4.secure.

        collection_documents = self.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesCles.DOCUMENT_LIBVAL_CLES_GROSFICHIERS,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                'fuuid': evenement['fuuid'],
            }
        }
        document = collection_documents.find_one(filtre)
        # Note: si le document n'est pas trouve, on repond acces refuse (obfuscation)
        reponse = {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_REFUSE}
        if document is not None:
            self._logger.debug("Document de cles pour grosfichiers: %s" % str(document))
            if acces_permis:
                cle_secrete = self._gestionnaire.decrypter_cle(document['cles'])
                cle_secrete_reencryptee, fingerprint = self._gestionnaire.crypter_cle(
                    cle_secrete, enveloppe_certificat.certificat)
                reponse = {
                    'cle': b64encode(cle_secrete_reencryptee).decode('utf-8'),
                    'iv': document['iv'],
                    Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_PERMIS
                }

        self._gestionnaire.generateur_transactions.transmettre_reponse(
            reponse, properties.reply_to, properties.correlation_id
        )

    def transmettre_cle_document(self, evenement, properties):
        """
        Verifie si la requete de cle est valide, puis transmet une reponse (cle re-encryptee ou acces refuse)
        :param evenement:
        :param properties:
        :return:
        """
        self._logger.debug("Transmettre cle document a %s" % properties.reply_to)

        # Verifier que la signature de la requete est valide - c'est fort probable, il n'est pas possible de
        # se connecter a MQ sans un certificat verifie. Mais s'assurer qu'il n'y ait pas de "relais" via un
        # messager qui a acces aux noeuds. La signature de la requete permet de faire cette verification.
        certificat_demandeur = self.gestionnaire.verificateur_transaction.verifier(evenement)
        enveloppe_certificat = certificat_demandeur
        # Aucune exception lancee, la signature de requete est valide et provient d'un certificat autorise et connu

        fingerprint_demande = evenement.get('fingerprint')
        if fingerprint_demande is not None:
            self._logger.debug("Re-encryption de la cle secrete avec certificat %s" % fingerprint_demande)
            try:
                enveloppe_certificat = self.gestionnaire.verificateur_certificats.charger_certificat(fingerprint=fingerprint_demande)

                # S'assurer que le certificat est d'un type qui permet d'exporter le contenu
                if ConstantesGenerateurCertificat.ROLE_COUPDOEIL_NAVIGATEUR in enveloppe_certificat.get_roles:
                    pass
                elif ConstantesGenerateurCertificat.ROLE_DOMAINES in certificat_demandeur.get_roles:
                    # Le middleware a le droit de demander une cle pour un autre composant
                    pass
                else:
                    self._logger.warning("Refus decrryptage cle avec fingerprint %s" % fingerprint_demande)
                    enveloppe_certificat = None
            except CertificatInconnu:
                enveloppe_certificat = None

        reponse = {Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_REFUSE}
        acces_permis = enveloppe_certificat is not None
        self._logger.debug(
            "Verification signature requete cle document. Cert: %s" % str(enveloppe_certificat.fingerprint_ascii))

        collection_documents = self.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesCles.DOCUMENT_LIBVAL_CLES_DOCUMENT,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: evenement[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS]
        }
        document = collection_documents.find_one(filtre)
        # Note: si le document n'est pas trouve, on repond acces refuse (obfuscation)
        if document is not None:
            self._logger.debug("Document de cles pour grosfichiers: %s" % str(document))
            if acces_permis:
                cle_secrete = self._gestionnaire.decrypter_cle(document['cles'])
                cle_secrete_reencryptee, fingerprint = self._gestionnaire.crypter_cle(
                    cle_secrete, enveloppe_certificat.certificat)
                reponse = {
                    'cle': b64encode(cle_secrete_reencryptee).decode('utf-8'),
                    'iv': document['iv'],
                    Constantes.SECURITE_LIBELLE_REPONSE: Constantes.SECURITE_ACCES_PERMIS
                }

        self._gestionnaire.generateur_transactions.transmettre_reponse(
            reponse, properties.reply_to, properties.correlation_id
        )


class ProcessusReceptionCles(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def traitement_regenerer(self, id_transaction, parametres_processus):
        """ Aucun traitement necessaire, le resultat est re-sauvegarde sous une nouvelle transaction """
        pass

    def recrypterCle(self, cle_secrete_encryptee):
        cert_maitredescles = self._controleur.gestionnaire.get_certificat
        fingerprint_certmaitredescles = b64encode(cert_maitredescles.fingerprint(hashes.SHA1())).decode('utf-8')
        cles_secretes_encryptees = {fingerprint_certmaitredescles: cle_secrete_encryptee}

        cle_secrete = self._controleur.gestionnaire.decrypter_contenu(cle_secrete_encryptee)
        # self._logger.debug("Cle secrete: %s" % cle_secrete)

        # Re-encrypter la cle secrete avec les cles backup
        if self._controleur.gestionnaire.get_certificats_backup is not None:
            for backup in self._controleur.gestionnaire.get_certificats_backup:
                cle_secrete_backup = backup.public_key().encrypt(
                    cle_secrete,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                fingerprint = b64encode(backup.fingerprint(hashes.SHA1())).decode('utf-8')
                cles_secretes_encryptees[fingerprint] = b64encode(cle_secrete_backup).decode('utf-8')

        return cles_secretes_encryptees

    def generer_transaction_majcles(self, sujet):
        generateur_transaction = self.generateur_transactions

        transaction_nouvellescles = ConstantesMaitreDesCles.DOCUMENT_TRANSACTION_CONSERVER_CLES.copy()
        transaction_nouvellescles[ConstantesMaitreDesCles.TRANSACTION_CHAMP_SUJET_CLE] = sujet
        transaction_nouvellescles[ConstantesMaitreDesCles.TRANSACTION_CHAMP_CLES] = \
            self.parametres['cles_secretes_encryptees']
        transaction_nouvellescles['iv'] = self.parametres['iv']

        # Copier les champs d'identification de ce document
        transaction_nouvellescles[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE] = \
            self.parametres[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        transaction_nouvellescles[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID] = \
            self.parametres[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        transaction_nouvellescles[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS] = \
            self.parametres[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS]

        # La transaction va mettre a jour (ou creer) les cles pour
        generateur_transaction.soumettre_transaction(
            transaction_nouvellescles,
            ConstantesMaitreDesCles.TRANSACTION_MAJ_DOCUMENT_CLES,
            version=ConstantesMaitreDesCles.TRANSACTION_VERSION_COURANTE
        )


class ProcessusNouvelleCleGrosFichier(ProcessusReceptionCles):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traitement_regenerer(self, id_transaction, parametres_processus):
        """ Aucun traitement necessaire, le resultat est re-sauvegarde sous une nouvelle transaction """
        pass

    def initiale(self):
        transaction = self.transaction

        # Decrypter la cle secrete et la re-encrypter avec toutes les cles backup
        cle_secrete_encryptee = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_CLESECRETE]
        cles_secretes_encryptees = self.recrypterCle(cle_secrete_encryptee)
        identificateurs_document = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS]

        self.set_etape_suivante(ProcessusNouvelleCleGrosFichier.generer_transaction_cles_backup.__name__)

        return {
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: identificateurs_document,
            'fuuid': identificateurs_document['fuuid'],
            'cles_secretes_encryptees': cles_secretes_encryptees,
            'iv': transaction['iv'],
        }

    def generer_transaction_cles_backup(self):
        """
        Sauvegarder les cles de backup sous forme de transaction dans le domaine MaitreDesCles.
        Va aussi declencher la mise a jour du document de cles associe.
        :return:
        """
        self.generer_transaction_majcles(ConstantesMaitreDesCles.DOCUMENT_LIBVAL_CLES_GROSFICHIERS)
        self.set_etape_suivante(ProcessusNouvelleCleGrosFichier.mettre_token_resumer_transaction.__name__)

    def mettre_token_resumer_transaction(self):
        """
        Mettre le token pour permettre a GrosFichier de resumer son processus de sauvegarde du fichier.
        :return:
        """
        generateur_transaction = self.generateur_transactions
        transaction_resumer = ConstantesMaitreDesCles.DOCUMENT_TRANSACTION_GROSFICHIERRESUME.copy()
        transaction_resumer['fuuid'] = self.parametres['fuuid']
        domaine_routing = ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_CLES_RECUES

        # La transaction va mettre permettre au processu GrosFichiers.nouvelleVersion de continuer
        self._logger.debug("Transmission nouvelle transaction cle recues pour GrosFichier")
        generateur_transaction.soumettre_transaction(transaction_resumer, domaine_routing)

        self.set_etape_suivante()  # Termine
        return {'resumer': transaction_resumer}


class ProcessusMAJDocumentCles(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement, TransactionDocumentMajClesVersionMapper())
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def initiale(self):
        transaction = self.transaction

        # Extraire les cles de document de la transaction (par processus d'elimination)
        cles_document = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE:
                transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE],
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS:
                transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS],
        }

        contenu_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_SUJET_CLE],
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            'iv': transaction['iv'],
        }
        contenu_on_insert.update(cles_document)

        contenu_date = {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: {'$type': 'date'},
        }

        contenu_set = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
        }
        for fingerprint in transaction['cles'].keys():
            cle_dict = 'cles.%s' % fingerprint
            valeur = transaction['cles'].get(fingerprint)
            contenu_set[cle_dict] = valeur

        if transaction.get(ConstantesMaitreDesCles.DOCUMENT_SECURITE) is not None:
            contenu_set[ConstantesMaitreDesCles.DOCUMENT_SECURITE] = \
                transaction[ConstantesMaitreDesCles.DOCUMENT_SECURITE]
        else:
            # Par defaut, on met le document en mode secure
            contenu_on_insert[ConstantesMaitreDesCles.DOCUMENT_SECURITE] = Constantes.SECURITE_SECURE

        operations_mongo = {
            '$set': contenu_set,
            '$currentDate': contenu_date,
            '$setOnInsert': contenu_on_insert,
        }

        collection_documents = self.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_DOCUMENTS_NOM)
        self.__logger.debug("Operations: %s" % str({'filtre': cles_document, 'operation': operations_mongo}))

        resultat_update = collection_documents.update_one(filter=cles_document, update=operations_mongo, upsert=True)
        self._logger.info("_id du nouveau document MaitreDesCles: %s" % str(resultat_update.upserted_id))

        self.set_etape_suivante()  # Termine


class ProcessusNouvelleCleDocument(ProcessusReceptionCles):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traitement_regenerer(self, id_transaction, parametres_processus):
        """ Aucun traitement necessaire, le resultat est re-sauvegarde sous une nouvelle transaction """
        pass

    def initiale(self):
        transaction = self.transaction
        domaine = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_DOMAINE]
        # UUID du contenu, pas celui dans en-tete
        uuid_transaction_doc = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        iddoc = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS]

        # Decrypter la cle secrete et la re-encrypter avec toutes les cles backup
        cle_secrete_encryptee = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_CLESECRETE]
        cles_secretes_encryptees = self.recrypterCle(cle_secrete_encryptee)
        self._logger.debug("Cle secrete encryptee: %s" % cle_secrete_encryptee)

        self.set_etape_suivante(ProcessusNouvelleCleDocument.generer_transaction_cles_backup.__name__)

        return {
            'domaine': domaine,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_transaction_doc,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: iddoc,
            'cles_secretes_encryptees': cles_secretes_encryptees,
            'iv': transaction['iv'],
        }

    def generer_transaction_cles_backup(self):
        """
        Sauvegarder les cles de backup sous forme de transaction dans le domaine MaitreDesCles.
        Va aussi declencher la mise a jour du document de cles associe.
        :return:
        """
        self.generer_transaction_majcles(ConstantesMaitreDesCles.DOCUMENT_LIBVAL_CLES_DOCUMENT)

        self.set_etape_suivante(ProcessusNouvelleCleDocument.mettre_token_resumer_transaction.__name__)

    def mettre_token_resumer_transaction(self):
        """
        Mettre le token pour permettre a GrosFichier de resumer son processus de sauvegarde du fichier.
        :return:
        """
        generateur_transaction = self.generateur_transactions
        identificateurs_document = self.parametres[ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS]
        transaction_resumer = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE:
                self.parametres[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE],
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID:
                self.parametres[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: identificateurs_document,
        }

        domaine_routing = '%s.%s' % (
            self.parametres['domaine'], ConstantesMaitreDesCles.TRANSACTION_DOMAINES_DOCUMENT_CLESRECUES)

        # La transaction va mettre permettre au processu GrosFichiers.nouvelleVersion de continuer
        self._logger.debug("Transmission nouvelle transaction cle recues pour %s" % domaine_routing)
        generateur_transaction.soumettre_transaction(transaction_resumer, domaine_routing)

        self.set_etape_suivante()  # Termine
        return {'resumer': transaction_resumer}


class ProcessusRenouvellerCertificat(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traitement_regenerer(self, id_transaction, parametres_processus):
        """ Aucun traitement necessaire, le nouveau cert est re-sauvegarde sous une nouvelle transaction dans PKI """
        pass

    def initiale(self):
        transaction = self.transaction
        role = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_ROLE_CERTIFICAT]
        node = transaction['node']

        # Reverifier la signature de la transaction (eviter alteration dans la base de donnees)
        # Extraire certificat et verifier type. Doit etre: maitredescles ou deployeur.
        enveloppe_cert = self._controleur.verificateur_transaction.verifier(transaction)
        roles_cert = enveloppe_cert.get_roles
        if enveloppe_cert.subject_organization_name == self._controleur.configuration.idmg and \
            'deployeur' in roles_cert or 'maitredescles' in roles_cert:
            # Le deployeur et le maitre des cles ont l'autorisation de renouveller n'importe quel certificat
            # Coupdoeil a tous les acces au niveau secure
            self.set_etape_suivante(ProcessusRenouvellerCertificat.generer_cert.__name__)
        else:
            self.set_etape_suivante(ProcessusRenouvellerCertificat.refuser_generation.__name__)
            return {
                'autorise': False,
                'role': role,
                'description': 'demandeur non autorise a renouveller ce certificat',
                'roles_demandeur': roles_cert
            }

        return {
            'autorise': True,
            'role': role,
            'roles_demandeur': roles_cert,
            'node': node,
        }

    def generer_cert(self):
        """
        Generer cert et creer nouvelle transaction pour PKI
        :return:
        """
        transaction = self.transaction
        role = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_ROLE_CERTIFICAT]
        node_name = self.parametres['node']
        csr_bytes = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_CSR].encode('utf-8')

        # Trouver generateur pour le role
        generateur = self._controleur.gestionnaire.renouvelleur_certificat
        clecert = generateur.renouveller_avec_csr(role, node_name, csr_bytes)

        # Generer nouvelle transaction pour sauvegarder le certificat
        transaction = {
            ConstantesPki.LIBELLE_CERTIFICAT_PEM: clecert.cert_bytes.decode('utf-8'),
            ConstantesPki.LIBELLE_FINGERPRINT: clecert.fingerprint,
            ConstantesPki.LIBELLE_SUBJECT: clecert.formatter_subject(),
            ConstantesPki.LIBELLE_NOT_VALID_BEFORE: int(clecert.not_valid_before.timestamp()),
            ConstantesPki.LIBELLE_NOT_VALID_AFTER: int(clecert.not_valid_after.timestamp()),
            ConstantesPki.LIBELLE_SUBJECT_KEY: clecert.skid,
            ConstantesPki.LIBELLE_AUTHORITY_KEY: clecert.akid,
        }
        self._controleur.generateur_transactions.soumettre_transaction(
            transaction,
            domaine=ConstantesPki.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT
        )

        self.set_etape_suivante()  # Termine - va repondre automatiquement au deployeur dans finale()

        return {
            'cert': clecert.cert_bytes.decode('utf-8'),
            'fullchain': clecert.chaine,
        }

    def refuser_generation(self):
        """
        Refuser la creation d'un nouveau certificat.
        :return:
        """
        # Repondre au demandeur avec le refus

        self.set_etape_suivante()  # Termine


class ProcessusSignerCertificatNoeud(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traitement_regenerer(self, id_transaction, parametres_processus):
        """ Aucun traitement necessaire, le nouveau cert est re-sauvegarde sous une nouvelle transaction dans PKI """
        pass

    def initiale(self):
        transaction = self.transaction
        domaines = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_DOMAINES]

        # Reverifier la signature de la transaction (eviter alteration dans la base de donnees)
        # Extraire certificat et verifier type. Doit etre: maitredescles ou deployeur.
        enveloppe_cert = self._controleur.verificateur_transaction.verifier(transaction)
        roles_cert = enveloppe_cert.get_roles
        if enveloppe_cert.subject_organization_name == self._controleur.configuration.idmg and \
            'coupdoeil' in roles_cert or 'deployeur' in roles_cert:
            # Le coupdoeil a l'autorisation de signer n'importe quel certificat
            self.set_etape_suivante(ProcessusSignerCertificatNoeud.generer_cert.__name__)
        else:
            self.set_etape_suivante(ProcessusSignerCertificatNoeud.refuser_generation.__name__)
            return {
                'autorise': False,
                'domaines': domaines,
                'description': 'demandeur non autorise a signer ce certificat',
                'roles_demandeur': roles_cert
            }

        return {
            'autorise': True,
            'domaines': domaines,
            'roles_demandeur': roles_cert,
        }

    def generer_cert(self):
        """
        Generer cert et creer nouvelle transaction pour PKI
        :return:
        """
        transaction = self.transaction
        domaines = self.parametres['domaines']
        csr_bytes = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_CSR].encode('utf-8')

        # Trouver generateur pour le role
        renouvelleur = self._controleur.gestionnaire.renouvelleur_certificat
        clecert = renouvelleur.signer_noeud(csr_bytes, domaines)

        # Generer nouvelle transaction pour sauvegarder le certificat
        transaction = {
            ConstantesPki.LIBELLE_CERTIFICAT_PEM: clecert.cert_bytes.decode('utf-8'),
            ConstantesPki.LIBELLE_FINGERPRINT: clecert.fingerprint,
            ConstantesPki.LIBELLE_SUBJECT: clecert.formatter_subject(),
            ConstantesPki.LIBELLE_NOT_VALID_BEFORE: int(clecert.not_valid_before.timestamp()),
            ConstantesPki.LIBELLE_NOT_VALID_AFTER: int(clecert.not_valid_after.timestamp()),
            ConstantesPki.LIBELLE_SUBJECT_KEY: clecert.skid,
            ConstantesPki.LIBELLE_AUTHORITY_KEY: clecert.akid,
        }
        self._controleur.generateur_transactions.soumettre_transaction(
            transaction,
            ConstantesPki.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT
        )

        # Creer une commande pour que le monitor genere le compte sur RabbitMQ
        commande_creation_compte = {
            ConstantesPki.LIBELLE_CERTIFICAT_PEM: clecert.cert_bytes.decode('utf-8'),
        }
        self._controleur.generateur_transactions.transmettre_commande(
            commande_creation_compte,
            'commande.monitor.ajouterCompteMq'
        )

        self.set_etape_suivante()  # Termine - va repondre automatiquement au deployeur dans finale()

        return {
            'cert': clecert.cert_bytes.decode('utf-8'),
            'fullchain': clecert.chaine,
        }

    def refuser_generation(self):
        """
        Refuser la creation d'un nouveau certificat.
        :return:
        """
        # Repondre au demandeur avec le refus

        self.set_etape_suivante()  # Termine


class ProcessusDeclasserCleGrosFichier(MGProcessusTransaction):

    def initiale(self):
        transaction = self.transaction
        self._logger.warning("Declasser grosfichier, transmettre cle secrete decryptee pour %s" % transaction['fuuid'])

        # Verifier que la signature de la requete est valide - c'est fort probable, il n'est pas possible de
        # se connecter a MQ sans un certificat verifie. Mais s'assurer qu'il n'y ait pas de "relais" via un
        # messager qui a acces aux noeuds. La signature de la requete permet de faire cette verification.
        enveloppe_certificat = self.controleur.verificateur_transaction.verifier(transaction)
        # Aucune exception lancee, la signature de transaction est valide et provient d'un certificat autorise et connu

        acces_permis = True  # Pour l'instant, les noeuds peuvent tout le temps obtenir l'acces a 4.secure.
        self._logger.debug(
            "Verification signature requete cle grosfichier. Cert: %s" % str(enveloppe_certificat.fingerprint_ascii))

        fuuid = transaction['fuuid']

        if acces_permis:
            cle_decryptee = self.controleur.gestionnaire.decrypter_grosfichier(fuuid)

            transaction = cle_decryptee.copy()
            transaction['fuuid'] = fuuid

            self.controleur.generateur_transactions.soumettre_transaction(
                transaction, ConstantesGrosFichiers.TRANSACTION_CLESECRETE_FICHIER
            )

        self.set_etape_suivante()  # Termine


class ProcessusGenererCertificatNavigateur(MGProcessusTransaction):
    """
    Generer un certificat pour un navigateur a partir d'une cle publique.
    """

    def initiale(self):
        transaction = self.transaction

        # Reverifier la signature de la transaction (eviter alteration dans la base de donnees)
        # Extraire certificat et verifier type. Doit etre: maitredescles ou deployeur.
        enveloppe_cert = self._controleur.verificateur_transaction.verifier(transaction)
        roles_cert = enveloppe_cert.get_roles
        if enveloppe_cert.subject_organization_name == self._controleur.configuration.idmg and \
                'coupdoeil' in roles_cert:
            # Le coupdoeil peut demander un certificat de navigateur
            self.set_etape_suivante(ProcessusSignerCertificatNoeud.generer_cert.__name__)
        else:
            self.set_etape_suivante(ProcessusSignerCertificatNoeud.refuser_generation.__name__)
            return {
                'autorise': False,
                'description': 'demandeur non autorise a demander la signateur de ce certificat',
                'roles_demandeur': roles_cert
            }

        return {
            'autorise': True,
            'roles_demandeur': roles_cert,
        }

    def generer_cert(self):
        """
        Generer cert et creer nouvelle transaction pour PKI
        :return:
        """
        transaction = self.transaction
        public_key_str = transaction['cle_publique']
        wrapped_public_key = PemHelpers.wrap_public_key(public_key_str)

        sujet = transaction['sujet']

        # Trouver generateur pour le role
        renouvelleur = self._controleur.gestionnaire.renouvelleur_certificat
        clecert = renouvelleur.signer_navigateur(wrapped_public_key, sujet)

        # Generer nouvelle transaction pour sauvegarder le certificat
        transaction = {
            ConstantesPki.LIBELLE_CERTIFICAT_PEM: clecert.cert_bytes.decode('utf-8'),
            ConstantesPki.LIBELLE_FINGERPRINT: clecert.fingerprint,
            ConstantesPki.LIBELLE_SUBJECT: clecert.formatter_subject(),
            ConstantesPki.LIBELLE_NOT_VALID_BEFORE: int(clecert.not_valid_before.timestamp()),
            ConstantesPki.LIBELLE_NOT_VALID_AFTER: int(clecert.not_valid_after.timestamp()),
            ConstantesPki.LIBELLE_SUBJECT_KEY: clecert.skid,
            ConstantesPki.LIBELLE_AUTHORITY_KEY: clecert.akid,
        }
        self._controleur.generateur_transactions.soumettre_transaction(
            transaction,
            ConstantesPki.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT
        )

        # Creer une reponse pour coupdoeil
        info_cert = transaction.copy()
        del info_cert[ConstantesPki.LIBELLE_CERTIFICAT_PEM]

        self.set_etape_suivante()  # Termine - va repondre automatiquement

        return {
            'certificat_info': info_cert,
            'cert': clecert.cert_bytes.decode('utf-8'),
            'fullchain': clecert.chaine,
        }

    def refuser_generation(self):
        """
        Refuser la creation d'un nouveau certificat.
        :return:
        """
        # Repondre au demandeur avec le refus

        self.set_etape_suivante()  # Termine


class ProcessusGenererDemandeInscription(MGProcessusTransaction):
    """
    Generer une nouvelle transaction pour l'Annuaire, va servir a demander l'acces a une MilleGrille tierce
    """

    def initiale(self):
        """
        Effecuter une requete pour obtenir la plus recente fiche privee
        """
        domaine = ConstantesAnnuaire.REQUETE_FICHE_PRIVEE
        self.set_requete(domaine, {})

        self.set_etape_suivante(ProcessusGenererDemandeInscription.demander_csr_connecteurs.__name__)

    def demander_csr_connecteurs(self):
        """
        Demander de nouveaux CSR aupres des connecteurs
        """

        domaine = 'inter.genererCsr'
        self.set_requete(domaine, {})

        self.set_etape_suivante(ProcessusGenererDemandeInscription.generer_transaction_annuaire.__name__)

    def generer_transaction_annuaire(self):
        """
        Generer la transaction signee pour l'Annuaire.
        """
        transaction = self.transaction

        idmg = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]
        fiche_privee = self.parametres['reponse'][0]
        csr_reponse = self.parametres['reponse'][1]

        csr = csr_reponse['csr']
        csr_correlation = csr_reponse['correlation']

        certificats_existants = list()
        certificats_existants.append(fiche_privee[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT_RACINE])
        certificats_existants.append(fiche_privee[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT])
        try:
            certificats_existants.extend(fiche_privee[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICATS_INTERMEDIAIRES])
        except TypeError:
            pass  # Array vide, OK
        try:
            certificats_existants.extend(fiche_privee[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT_ADDITIONNELS])
        except TypeError:
            pass  # Array vide, OK

        with open(self.controleur.configuration.pki_certfile, 'r') as fichier:
            certfile_fullchain = fichier.read()
            certs_chain = list()
            for cert in certfile_fullchain.split('-----END CERTIFICATE-----\n'):
                if cert != '' and cert not in certificats_existants:
                    cert = cert + '-----END CERTIFICATE-----\n'
                    certs_chain.append(cert)

        nouvelle_transaction = {
            ConstantesAnnuaire.LIBELLE_DOC_IDMG_SOLLICITE: idmg,
            ConstantesAnnuaire.LIBELLE_DOC_FICHE_PRIVEE: fiche_privee,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_CSR: csr,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_CSR_CORRELATION: csr_correlation,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_TYPEDEMANDE: ConstantesMaitreDesCles.TYPE_DEMANDE_INSCRIPTION,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_FULLCHAIN: certs_chain,
        }

        # Transmettre la transaction. La correlation permet au domaine de savoir que la transaction
        # doit etre sauvegardee et non actionnee (certificat signe)
        domaine = ConstantesAnnuaire.TRANSACTION_DEMANDER_INSCRIPTION
        self.generateur_transactions.soumettre_transaction(nouvelle_transaction, domaine)

        self.set_etape_suivante()  # Termine


class TransactionDocumentMajClesVersionMapper:
    """
    Mapper de versions pour la transaction DocumentCles (GrosFichiers)
    """

    def __init__(self):
        self.__mappers = {
            '4': self.map_version_4_to_current,
            '5': self.map_version_5_to_current,
        }

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def map_version_to_current(self, transaction):
        version = transaction[
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION]
        mapper = self.__mappers[str(version)]
        if mapper is None:
            raise ValueError("Version inconnue: %s" % str(version))

        mapper(transaction)

    def map_version_4_to_current(self, transaction):
        if transaction.get('fuuid') is not None:
            fuuid = transaction.get('fuuid')
            # Type GrosFichiers
            document = {
                Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: ConstantesGrosFichiers.DOMAINE_NOM,
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: fuuid,
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                    ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: fuuid,
                }
            }
            del transaction['fuuid']
            transaction.update(document)
            self.__logger.debug("Mapping V4->5 transaction GrosFichiers: %s" % str(transaction))
        elif transaction.get('mg-libelle'):
            document = {
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: transaction['uuid'],
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                    Constantes.DOCUMENT_INFODOC_LIBELLE: transaction['mg-libelle'],
                }
            }
            del transaction['mg-libelle']
            transaction.update(document)
            self.__logger.debug("Mapping V4->5 transaction Parametres: %s" % str(transaction))

    def map_version_5_to_current(self, transaction):
        """ Version courante, rien a faire """
        pass


class ProcessusGenererCertificatPourTiers(MGProcessusTransaction):
    """
    Genere un certificat de connexion pour un tiers
    """

    def initiale(self):
        domaine = ConstantesAnnuaire.REQUETE_FICHE_PRIVEE
        self.set_requete(domaine, {})

        self.set_etape_suivante(ProcessusGenererCertificatPourTiers.signer_demande.__name__)

    def signer_demande(self):
        """
        Extrait le CSR et genere un nouveau certificat de connecteur.
        """
        fiche_privee = self.parametres['reponse'][0]

        transaction = self.transaction
        fiche_privee_tiers = transaction[ConstantesAnnuaire.LIBELLE_DOC_FICHE_PRIVEE]
        idmg_tiers = fiche_privee_tiers[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]
        csr = transaction[ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_CSR]

        clecert = self.controleur.gestionnaire.generer_certificat_connecteur(idmg_tiers, csr)

        # Sauvegarder certificat pour tiers et transmettre vers tiers
        self._transmettre_a_pki(clecert)
        self._transmettre_a_annuaire(transaction, idmg_tiers, clecert, fiche_privee)

        self.set_etape_suivante()

    def _transmettre_a_annuaire(self, transaction, idmg_tiers, clecert: EnveloppeCleCert, fiche_privee: dict):

        fiche_privee_filtree = DocElemFilter.retirer_champs_doc_transaction(fiche_privee)

        with open(self.controleur.configuration.pki_certfile, 'r') as fichier:
            cert_fullchain = PemHelpers.split_certificats(fichier.read())

        nouvelle_transaction_annuaire = {
            ConstantesAnnuaire.LIBELLE_DOC_IDMG_SOLLICITE: transaction[ConstantesAnnuaire.LIBELLE_DOC_IDMG_SOLLICITE],
            ConstantesAnnuaire.LIBELLE_DOC_EXPIRATION: int(clecert.not_valid_after.timestamp()),
            ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT: clecert.cert_bytes.decode('utf-8'),
            ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_CORRELATION: transaction[ConstantesAnnuaire.LIBELLE_DOC_DEMANDES_CORRELATION],
            ConstantesAnnuaire.LIBELLE_DOC_FICHE_PRIVEE: fiche_privee_filtree,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_FULLCHAIN: cert_fullchain,
        }
        self._controleur.generateur_transactions.soumettre_transaction(
            nouvelle_transaction_annuaire, ConstantesAnnuaire.TRANSACTION_SIGNATURE_INSCRIPTION_TIERS,
            idmg_destination=idmg_tiers)

    def _transmettre_a_pki(self, clecert):
        # Generer nouvelle transaction pour sauvegarder le certificat
        transaction = {
            ConstantesPki.LIBELLE_CERTIFICAT_PEM: clecert.cert_bytes.decode('utf-8'),
            ConstantesPki.LIBELLE_FINGERPRINT: clecert.fingerprint,
            ConstantesPki.LIBELLE_SUBJECT: clecert.formatter_subject(),
            ConstantesPki.LIBELLE_NOT_VALID_BEFORE: int(clecert.not_valid_before.timestamp()),
            ConstantesPki.LIBELLE_NOT_VALID_AFTER: int(clecert.not_valid_after.timestamp()),
            ConstantesPki.LIBELLE_SUBJECT_KEY: clecert.skid,
            ConstantesPki.LIBELLE_AUTHORITY_KEY: clecert.akid,
        }
        self._controleur.generateur_transactions.soumettre_transaction(
            transaction,
            ConstantesPki.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT,
        )
