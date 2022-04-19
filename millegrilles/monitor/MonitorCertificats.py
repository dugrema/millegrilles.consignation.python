import datetime
import json
import logging
import os
import requests
import secrets
import tempfile
import pytz

from base64 import b64decode, b64encode
from os import path
from typing import cast, Optional

import docker
from docker.types import SecretReference
from docker.errors import APIError
from cryptography import x509
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.monitor.MonitorConstantes import GenerationCertificatNonSupporteeException
from millegrilles.util.X509Certificate import EnveloppeCleCert, RenouvelleurCertificat, \
    ConstantesGenerateurCertificat, GenerateurCertificatNginxSelfsigned
from millegrilles.monitor import MonitorConstantes


class GestionnaireCertificats:

    MONITOR_CERT_PATH = 'monitor_cert_path'
    MONITOR_KEY_FILE = 'monitor_key_file'
    MONITOR_KEY_FILENAME = 'pki.monitor.key'

    def __init__(self, docker_client: docker.DockerClient, service_monitor, **kwargs):
        self._docker = docker_client
        self._service_monitor = service_monitor
        self._date: str = cast(str, None)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.certificats = dict()
        self._clecert_millegrille: EnveloppeCleCert = cast(EnveloppeCleCert, None)
        self._clecert_intermediaire: EnveloppeCleCert = cast(EnveloppeCleCert, None)
        self.clecert_monitor: EnveloppeCleCert = cast(EnveloppeCleCert, None)

        self.secret_path = kwargs.get('secrets')
        self._mode_insecure = kwargs.get('insecure') or False

        self.maj_date()

        self._nodename = self._docker.info()['Name']
        self.idmg: str = cast(str, None)

        self.__cles_memorisees = dict()

        cert_pem = kwargs.get('millegrille_cert_pem')
        if cert_pem:
            self._clecert_millegrille = EnveloppeCleCert()
            self._clecert_millegrille.cert_from_pem_bytes(cert_pem.encode('utf-8'))
        else:
            # Tenter de charger le certificat a partir de millegrille.configuration
            try:
                millegrille_pem_config = self._docker.configs.get('pki.millegrille.cert')
                json_millegrille = b64decode(millegrille_pem_config.attrs['Spec']['Data'])
                self._clecert_millegrille = EnveloppeCleCert()
                self._clecert_millegrille.cert_from_pem_bytes(json_millegrille)

            except docker.errors.NotFound:
                self.__logger.info("millegrille.configuration abstente : Nouvelle MilleGrille, noeud principal.")

        # Calculer le IDMG a partir du certificat de MilleGrille
        if self._clecert_millegrille:
            self.idmg = self._clecert_millegrille.idmg
            self.__logger.info("Gestionnaire certificat, idmg : %s" % self.idmg)

    def maj_date(self):
        self._date = str(datetime.datetime.utcnow().strftime(MonitorConstantes.DOCKER_LABEL_TIME))

    def __preparer_label(self, name, date: str = None):
        if date is None:
            date = self._date
        params = {
            'name': name,
            'date': date,
        }
        name_docker = '%(name)s.%(date)s' % params
        return name_docker[0:64]  # Max 64 chars pour name docker

    def ajouter_config(self, name: str, data: bytes, date: str = None, labels: dict = None):
        if labels is not None:
            labels_config = labels.copy()
        else:
            labels_config = dict()
        labels_config['idmg'] = self.idmg
        labels_config['nom'] = name
        if date is not None:
            labels_config['date'] = date

        name_tronque = self.__preparer_label(name, date)
        self._docker.configs.create(name=name_tronque, data=data, labels=labels_config)

    def ajouter_secret(self, name: str, data: bytes, labels: dict = None):
        name_tronque = self.__preparer_label(name)
        if labels is not None:
            labels_config = labels.copy()
        else:
            labels_config = dict()
        labels_config['idmg'] = self.idmg
        labels_config['nom'] = name

        self._docker.secrets.create(name=name_tronque, data=data, labels=labels)

        if self._mode_insecure:
            try:
                os.mkdir(self.secret_path, 0o755)
            except FileExistsError:
                pass

            with open(path.join(self.secret_path, name_tronque), 'wb') as fichiers:
                fichiers.write(data)

        return name_tronque

    def __generer_private_key(self, generer_password=False, keysize=2048, public_exponent=65537):
        info_cle = dict()
        clecert = EnveloppeCleCert()
        clecert.generer_private_key(generer_password=generer_password)
        if generer_password:
            # info_cle['password'] = b64encode(secrets.token_bytes(16))
            info_cle['password'] = clecert.password

        # info_cle['cle'] = asymmetric.rsa.generate_private_key(
        #     public_exponent=public_exponent,
        #     key_size=keysize,
        #     backend=default_backend()
        # )

        info_cle['pem'] = clecert.private_key_bytes
        info_cle['clecert'] = clecert
        info_cle['cle'] = clecert.private_key

        return info_cle

    def generer_csr(self, type_cle: str = None, insecure=False, inserer_cle=True, generer_password=False):
        # Generer cle privee
        info_cle = self.__generer_private_key(generer_password=generer_password)

        # Generer CSR
        # node_name = self._docker.info()['Name']
        noeud_id = self._service_monitor.noeud_id
        builder = x509.CertificateSigningRequestBuilder()

        name_list = list()
        if type_cle:
            name_list.append(x509.NameAttribute(x509.name.NameOID.ORGANIZATIONAL_UNIT_NAME, type_cle))
        name_list.append(x509.NameAttribute(x509.name.NameOID.COMMON_NAME, noeud_id))

        if self.idmg:
            name_list.append(x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, self.idmg))
        name = x509.Name(name_list)
        builder = builder.subject_name(name)

        # request = builder.sign(info_cle['cle'], hashes.SHA256(), default_backend())
        request = builder.sign(info_cle['cle'], None, default_backend())
        request_pem = request.public_bytes(primitives.serialization.Encoding.PEM)
        info_cle['request'] = request_pem
        info_cle['cle_pem'] = info_cle['pem']

        self.__logger.debug("Request CSR : %s" % request_pem)

        cle_pem = info_cle['cle_pem']
        cle_passwd = info_cle.get('password')

        #if inserer_cle:
        #    label_key_inter = 'pki.%s.key' % type_cle
        #    self.ajouter_secret(label_key_inter, data=cle_pem)
        #    if cle_passwd:
        #        label_passwd_inter = 'pki.%s.passwd' % type_cle
        #        self.ajouter_secret(label_passwd_inter, data=cle_passwd)
        #    label_csr_inter = 'pki.%s.csr' % type_cle
        #    self.ajouter_config(label_csr_inter, data=request_pem)

        return info_cle

    def _charger_certificat_docker(self, nom_certificat) -> bytes:
        """
        Extrait un certificat de la config docker vers un fichier temporaire.
        Conserve le nom du fichier dans self.__certificats.
        :param nom_certificat:
        :return: Contenu du certificat en PEM
        """
        cert = MonitorConstantes.trouver_config(nom_certificat, self._docker)['config']
        cert_pem = b64decode(cert.attrs['Spec']['Data'])
        fp, fichier_cert = tempfile.mkstemp(dir='/tmp')
        try:
            os.write(fp, cert_pem)
            self.certificats[nom_certificat] = fichier_cert
        finally:
            os.close(fp)

        return cert_pem

    def recevoir_certificat(self, message: dict):
        self.__logger.info("Certificat recu :\n%s" % json.dumps(message, indent=2))
        chaines = message.get('chaines') or message['resultats']['chaines']

        for info_chaine in chaines['chaines']:
            pems = info_chaine['pems']

            # Identifier le role du certificat (OU)
            self.traiter_reception_certificat(pems)

        self._service_monitor.trigger_event_attente()

    def traiter_reception_certificat(self, pems):
        cert = pems[0]
        clecert = EnveloppeCleCert()
        clecert.cert_from_pem_bytes(cert.encode('utf-8'))
        subject_dict = clecert.formatter_subject()
        role = subject_dict['organizationalUnitName']

        # Trouver cle correspondante (date)
        label_role_cert = 'pki.%s.cert' % role
        label_role_key = 'pki.%s.key' % role
        info_role_key = self._service_monitor.gestionnaire_docker.trouver_secret(label_role_key)
        date_key = info_role_key['date']

        # Inserer la chaine de certificat
        chaine = '\n'.join(pems)
        self._service_monitor.gestionnaire_certificats.ajouter_config(label_role_cert, chaine, date_key)

    def reconfigurer_clecert(self, nom_cert, password=False):
        gestionnaire_docker = self._service_monitor.gestionnaire_docker
        config_reference = gestionnaire_docker.charger_config_recente(nom_cert)
        nom_cert = config_reference['config_reference']['config_name']
        nom_key = nom_cert.replace('cert', 'key')
        config_key = gestionnaire_docker.trouver_secret(nom_key)
        fichier_cert = '.'.join(nom_key.split('.')[0:3])
        secrets_a_configurer = [
            {'ref': config_key, 'filename': '%s.pem' % fichier_cert},
        ]

        if password:
            nom_passwd = nom_cert.replace('cert', 'passwd')
            fichier_passwd = '.'.join(nom_passwd.split('.')[0:3])
            config_passwd = gestionnaire_docker.trouver_secret(nom_passwd)
            secrets_a_configurer.append({'ref': config_passwd, 'filename': '%s.txt' % fichier_passwd})

        liste_secrets = list()
        for secret in secrets_a_configurer:
            # secret_reference = self.trouver_secret(secret_name)
            secret_reference = secret['ref']
            secret_reference['filename'] = secret['filename']
            secret_reference['uid'] = 0
            secret_reference['gid'] = 0
            secret_reference['mode'] = 0o444

            del secret_reference['date']  # Cause probleme lors du chargement du secret
            liste_secrets.append(SecretReference(**secret_reference))

        return {'secrets': liste_secrets}

    def sauvegarder_certificat_container(self, nom_certificat, clecert):
        path_secret_docker = path.join(MonitorConstantes.PATH_SOURCE_SECRET_DEFAUT, nom_certificat)

        if os.path.exists(path_secret_docker):
            secret_pem_bytes = clecert.private_key_bytes
            chaine = clecert.chaine
            ca_cert = clecert.ca

            self.__logger.info("Conserver certificat %s sous path secrets pour container" % nom_certificat)
            with open(path.join(path_secret_docker, 'cert.pem'), 'w') as fichier:
                fichier.write(''.join(chaine))
            with open(path.join(path_secret_docker, 'key.pem'), 'wb') as fichier:
                fichier.write(secret_pem_bytes)
            with open(path.join(path_secret_docker, 'millegrille.cert.pem'), 'w') as fichier:
                fichier.write(ca_cert)

    @property
    def idmg_tronque(self):
        return self.idmg[0:12]

    def memoriser_cle(self, role, cle_pem):
        self.__cles_memorisees[role] = cle_pem

    def _recuperer_cle_memorisee(self, role):
        cle = self.__cles_memorisees[role]
        del self.__cles_memorisees[role]
        return cle

    def set_clecert_millegrille(self, clecert_millegrille):
        self._clecert_millegrille = clecert_millegrille

    def set_clecert_intermediaire(self, clecert_intermediaire):
        self._clecert_intermediaire = clecert_intermediaire

    def charger_certificats(self):
        raise NotImplementedError()

    def generer_nouveau_idmg(self):
        raise NotImplementedError()

    def generer_clecert_module(self, role: str, common_name: str, nomcle: str = None, liste_dns: list = None, combiner_keycert=False) -> EnveloppeCleCert:
        raise GenerationCertificatNonSupporteeException()

    def verifier_eligibilite_renouvellement(self, clecert: EnveloppeCleCert):
        not_valid_after = clecert.not_valid_after
        not_valid_before = clecert.not_valid_before

        # Calculer 2/3 de la duree du certificat
        delta_2tiers = not_valid_after - not_valid_before
        delta_2tiers = delta_2tiers * 0.67
        date_eligible = not_valid_before + delta_2tiers
        if date_eligible < pytz.utc.localize(datetime.datetime.utcnow()):
            return True

        return False


class GestionnaireCertificatsSatellite(GestionnaireCertificats):

    def __init__(self, docker_client: docker.DockerClient, service_monitor, **kwargs):
        super().__init__(docker_client, service_monitor, **kwargs)
        self._service_monitor = service_monitor
        self._passwd_mq: str = cast(str, None)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._renouvelleur = RenouvelleurCertificat(service_monitor.idmg, dict(), None)
        
        # CSR pour le prochain certificat de cette instance satellite
        self.__csr_monitor: Optional[EnveloppeCleCert] = None

    def charger_certificats(self):
        secret_path = path.abspath(self.secret_path)
        os.makedirs(secret_path, exist_ok=True)  # Creer path secret, au besoin

        # Charger information certificat monitor
        try:
            cert_pem = self._charger_certificat_docker('pki.monitor.cert')
        except AttributeError:
            # Le certificat est introuvable - probablement un reset manuel (config supprimee manuellement)
            self.get_csr()  # Creer CSR si pas deja fait
        else:
            with open(path.join(secret_path, GestionnaireCertificats.MONITOR_KEY_FILENAME + '.pem'), 'rb') as fichiers:
                key_pem = fichiers.read()
            clecert_monitor = EnveloppeCleCert()
            clecert_monitor.from_pem_bytes(key_pem, cert_pem)

            if not clecert_monitor.is_valid_at_current_time:
                self.__logger.warning("Certificat de monitor est expire")
            else:
                self.clecert_monitor = clecert_monitor

                # Conserver reference au cert monitor pour middleware
                self.certificats[GestionnaireCertificats.MONITOR_CERT_PATH] = self.certificats['pki.monitor.cert']
                self.certificats[
                    GestionnaireCertificats.MONITOR_KEY_FILE] = GestionnaireCertificats.MONITOR_KEY_FILENAME + '.pem'

                # S'assurer que la cle de MilleGrille correspond au certificat (erreur de configuration...)
                if not self.clecert_monitor.cle_correspondent():
                    self.__logger.fatal("charger_certificats : La cle et certificat X.509 ne correspondent pas, on va tenter de reparer")
                    self._service_monitor.gestionnaire_docker.configurer_monitor()

            # Charger le certificat de millegrille
            self._charger_certificat_docker('pki.millegrille.cert')

    def generer_motsdepasse(self):
        """
        Genere les mots de passes pour composants internes de middleware
        :return:
        """
        pass  # Aucun mot de passe prive

    def get_csr(self):
        
        if self.__csr_monitor is None:
            self.__logger.info("Generer nouveau CSR pour le monitor")
            info_cle = self.generer_csr(ConstantesGenerateurCertificat.ROLE_MONITOR)
            self.__csr_monitor = info_cle
            
        return self.__csr_monitor['request']

    def get_infocle(self):
        return self.__csr_monitor

    def entretien_certificat(self):
        try:
            if self.clecert_monitor is not None:
                eligible = self.verifier_eligibilite_renouvellement(self.clecert_monitor)
                if eligible is True:
                    self.__logger.info("Certificat monitor eligible pour renouvellement, demande via MQ")

                    # Creer CSR si pas deja fait
                    csr = self.generer_csr()

                    # Demander un renouvellement via MQ
                    # Generer message a transmettre au monitor pour renouvellement
                    commande = {
                        'csr': csr,
                        'securite': Constantes.SECURITE_PUBLIC,
                    }

                    try:
                        self._service_monitor.connexion_middleware.generateur_transactions.transmettre_commande(
                            commande,
                            'commande.monitor.%s' % Constantes.ConstantesServiceMonitor.COMMANDE_SIGNER_NOEUD,
                            exchange=Constantes.SECURITE_PUBLIC,
                            correlation_id=ConstantesServiceMonitor.CORRELATION_RENOUVELLEMENT_CERTIFICAT,
                            reply_to=self._service_monitor.connexion_middleware.reply_q,
                            ajouter_certificats=True
                        )
                    except AttributeError:
                        self.__logger.warning("Connexion MQ pas prete, on ne peut pas renouveller le certificat de monitor")
                        if self.__logger.isEnabledFor(logging.DEBUG):
                            self.__logger.exception("Connexion MQ pas prete")

        except Exception:
            self.__logger.exception("Erreur entretien certificat monitor")

    def generer_clecert_module(self, role: str, common_name: str, nomcle: str = None, liste_dns: list = None,
                               combiner_keycert=False) -> EnveloppeCleCert:

        clecert = self._renouvelleur.preparer_csr_par_role(role, common_name, liste_dns)

        # Post vers certissuer pour signer avec l'autorite, obtenir le certificat
        requete = {'csr': clecert.csr_bytes.decode('utf-8'), 'role': role, 'liste_dns': liste_dns}
        # Signer avec certificat de monitor pour autoriser le certissuer
        # formatteur_message = self._service_monitor.get_formatteur_message(self.clecert_monitor)
        # requete_signee, uuid_transaction = formatteur_message.signer_message(requete, 'certissuer', action="signer",
        #                                                                      ajouter_chaine_certs=True)

        # url_certissuer = self.get_url_certissuer()
        # url_certissuer = url_certissuer + '/certissuerInterne/signerModule'
        # reponse = requests.post(url_certissuer, json=requete_signee, timeout=10)
        # reponse.raise_for_status()
        # reponse_json = reponse.json()

        connexion = self._service_monitor.connexion_middleware
        reponse_json, enveloppe = connexion.commande(requete, 'CorePki', action='signerCsr')

        try:
            chaine = reponse_json['certificat']
            if len(chaine) > 2:
                chaine = chaine[:2]  # Retirer cert millegrille (CA)
            clecert.chaine = chaine
            clecert.ca = reponse_json['ca']
        except KeyError:
            raise ErreurSignatureCertificatException("Erreur signature certificat pour role %s, reponse\n%s" % (role, json.dumps(reponse_json, indent=2)))

        if nomcle is None:
            nomcle = role

        chaine_certs = '\n'.join(chaine)
        secret = clecert.private_key_bytes

        # Verifier si on doit combiner le cert et la cle (requis pour Mongo)
        if combiner_keycert or role in [ConstantesGenerateurCertificat.ROLE_MONGO,
                                        ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS]:
            secret_str = [str(secret, 'utf-8')]
            secret_str.extend(chaine)
            secret = '\n'.join(secret_str).encode('utf-8')

        labels = {'mg_type': 'pki', 'role': role, 'common_name': common_name}

        self.ajouter_secret('pki.%s.key' % nomcle, secret, labels=labels)
        self.ajouter_config('pki.%s.cert' % nomcle, chaine_certs.encode('utf-8'), labels=labels)

        return clecert


class GestionnaireCertificatsNoeudPublic(GestionnaireCertificatsSatellite):
    pass


class GestionnaireCertificatsNoeudPrive(GestionnaireCertificatsSatellite):
    pass


class GestionnaireCertificatsNoeudProtegeDependant(GestionnaireCertificatsNoeudPrive):

    def __init__(self, docker_client: docker.DockerClient, service_monitor, **kwargs):
        super().__init__(docker_client, service_monitor, **kwargs)
        self._passwd_mongo: str = cast(str, None)
        self._passwd_mongoxp: str = cast(str, None)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def generer_motsdepasse(self):
        """
        Genere les mots de passes pour composants internes de middleware
        :return:
        """
        super().generer_motsdepasse()

        passwd_mq = b64encode(secrets.token_bytes(32)).replace(b'=', b'')
        self.ajouter_secret('passwd.mq', passwd_mq)
        self._passwd_mq = str(passwd_mq, 'utf-8')
        # label_passwd_mq = 'passwd.mq.' + self._date
        # self._docker.secrets.create(name=label_passwd_mq, data=passwd_mq, labels={'millegrille': self.idmg})

        passwd_mongo = b64encode(secrets.token_bytes(32)).replace(b'=', b'')
        self.ajouter_secret('passwd.mongo', passwd_mongo)
        self._passwd_mongo = str(passwd_mongo, 'utf-8')

        passwd_mongoxpweb = b64encode(secrets.token_bytes(24)).replace(b'=', b'')
        self.ajouter_secret('passwd.mongoxpweb', passwd_mongoxpweb)
        self._passwd_mongoxp = str(passwd_mongoxpweb, 'utf-8')

        # if self._mode_insecure:
        #     try:
        #         os.mkdir('/var/opt/millegrilles/secrets', 0o755)
        #     except FileExistsError:
        #         pass
        #
        #     with open('/var/opt/millegrilles/secrets/passwd.mongo.txt', 'w') as fichiers:
        #         fichiers.write(self._passwd_mongo)
        #     with open('/var/opt/millegrilles/secrets/passwd.mongoxpweb.txt', 'w') as fichiers:
        #         fichiers.write(self._passwd_mongoxp)
        #
        #     try:
        #         os.mkdir('/var/opt/millegrilles/secrets', 0o700)
        #     except FileExistsError:
        #         pass
        #
        #     with open('/var/opt/millegrilles/secrets/passwd.mq.txt', 'w') as fichiers:
        #         fichiers.write(self._passwd_mq)

    def charger_certificats(self):
        secret_path = path.abspath(self.secret_path)

        # Charger mots de passes middleware
        with open(path.join(secret_path, ConstantesServiceMonitor.FICHIER_MONGO_MOTDEPASSE), 'r') as fichiers:
            self._passwd_mongo = fichiers.read()
        with open(path.join(secret_path, ConstantesServiceMonitor.FICHIER_MQ_MOTDEPASSE), 'r') as fichiers:
            self._passwd_mq = fichiers.read()

        # Charger information certificat monitor
        clecert_monitor = EnveloppeCleCert()
        with open(path.join(secret_path, 'pki.monitor_dependant.key.pem'), 'rb') as fichiers:
            key_pem = fichiers.read()
        try:
            cert_pem = self._charger_certificat_docker('pki.monitor_dependant.cert')
            clecert_monitor.from_pem_bytes(key_pem, cert_pem)

            # Conserver reference au cert monitor
            self.certificats[GestionnaireCertificats.MONITOR_CERT_PATH] = self.certificats['pki.monitor_dependant.cert']
            self.certificats[GestionnaireCertificats.MONITOR_KEY_FILE] = 'pki.monitor_dependant.key.pem'

        except AttributeError:
            self.__logger.info("Certificat monitor_dependant non trouve, on va l'attendre")
            clecert_monitor.key_from_pem_bytes(key_pem)

        self.clecert_monitor = clecert_monitor

        # Charger le certificat de millegrille, chaine pour intermediaire
        self._charger_certificat_docker('pki.millegrille.cert')

    def traiter_reception_certificat(self, pems):
        cert = pems[0]
        clecert = EnveloppeCleCert()
        clecert.cert_from_pem_bytes(cert.encode('utf-8'))
        subject_dict = clecert.formatter_subject()
        role = subject_dict['organizationalUnitName']

        if role == 'mongo':
            # Pour MongoDB on insere la cle (en memoire) et le nouveau certificat dans le meme secret (une key_cert)
            label_role_cert = 'pki.%s.cert' % role
            label_role_key = 'pki.%s.key' % role

            chaine = '\n'.join(pems)
            cle_mongo = self._recuperer_cle_memorisee(role)  # Note : efface la cle en memoire
            if not cle_mongo:
                raise ValueError("Cle mongo n'est pas presente en memoire")
            key_cert = str(cle_mongo, 'utf-8') + '\n' + chaine

            # Inserer la chaine de certificat
            nom_cle = self._service_monitor.gestionnaire_certificats.ajouter_secret(label_role_key, key_cert)
            date_key = nom_cle.split('.')[-1]
            self._service_monitor.gestionnaire_certificats.ajouter_config(label_role_cert, chaine, date_key)
        else:
            super().traiter_reception_certificat(pems)


class GestionnaireCertificatsNoeudProtegePrincipal(GestionnaireCertificatsNoeudProtegeDependant):

    def __init__(self, docker_client: docker.DockerClient, service_monitor, **kwargs):
        super().__init__(docker_client, service_monitor, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        # self.__renouvelleur = RenouvelleurCertificat(service_monitor.idmg, dict(), None)

    def get_url_certissuer(self):
        url_issuer = os.environ.get('MG_CERTISSUER_URL') or 'http://certissuer:8380'
        return url_issuer

    def recuperer_monitor_initial(self, info_installation: dict):
        """
        Sert a installer un certificat intermediaire dans le certissuer. Le certificat intermediaire (qui correspond
        au IDMG et au CSR sur le certissuer) est utilise comme mot de passe pour autoriser la signature du CSR monitor.
        :param info_installation: Data qui inclus le nouveau certificat intermediaire.
        :return:
        """
        idmg = info_installation['idmg']
        noeud_id = self._service_monitor.noeud_id
        clecert = self.generer_csr_monitor(idmg, noeud_id)

        # Copier parametres, ajouter le nouveau CSR
        commande_certissuer = {'idmg': idmg, 'chainePem': info_installation['chainePem'],
                               'csr_monitor': clecert.csr_bytes.decode('utf-8')}

        # Faire un POST avec l'information pour installer le certificat intermediaire et recuperer le cert monitor
        url_certissuer = self.get_url_certissuer()
        url_certissuer = url_certissuer + '/certissuerInterne/issuer'
        reponse = requests.post(url_certissuer, json=commande_certissuer, timeout=5)
        # reponse = requests.post("http://192.168.2.131:8380/certissuer/issuer", json=commande_certissuer, timeout=5)
        reponse.raise_for_status()
        reponse_json = reponse.json()
        cert_monitor = reponse_json['certificat_monitor']
        cert_ca = reponse_json['ca']

        # Charger le certificat, verifier correspondance
        chaine_cert = ''.join(cert_monitor).encode('utf-8')
        clecert.cert_from_pem_bytes(chaine_cert)
        if clecert.cle_correspondent() is False:
            raise Exception("erreur, cle prive/public ne correspondent pas")

        clecert_millegrille = EnveloppeCleCert()
        clecert_millegrille.cert_from_pem_bytes(cert_ca.encode('utf-8'))

        idmg_recu = clecert_millegrille.idmg
        if idmg_recu != idmg:
            raise Exception("Mismatch idmg recu : %s" % idmg_recu)

        # labels_millegrille = {'mg_type': 'pki', 'role': 'millegrille', 'common_name': noeud_id}
        try:
            self._docker.configs.create(name='pki.millegrille.cert', data=cert_ca)
        except APIError as apie:
            if apie.status_code != 409:
                raise apie

        secret = clecert.private_key_bytes
        labels = {'mg_type': 'pki', 'role': 'monitor', 'common_name': noeud_id}
        self.ajouter_secret('pki.monitor.key', secret, labels=labels)
        self.ajouter_config('pki.monitor.cert', chaine_cert, labels=labels)

        return clecert

    def generer_csr_monitor(self, idmg: str, noeud_id: str) -> EnveloppeCleCert:
        # Generer une nouveau CSR avec une cle privee pour le monitor
        clecert_monitor = EnveloppeCleCert()
        clecert_monitor.generer_private_key()

        # Generer CSR
        builder = x509.CertificateSigningRequestBuilder()
        name_list = list()
        name_list.append(x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, idmg))
        name_list.append(x509.NameAttribute(x509.name.NameOID.ORGANIZATIONAL_UNIT_NAME, u'monitor'))
        name_list.append(x509.NameAttribute(x509.name.NameOID.COMMON_NAME, noeud_id))
        name = x509.Name(name_list)
        builder = builder.subject_name(name)

        # request = builder.sign(clecert_monitor.private_key, hashes.SHA256(), default_backend())
        request = builder.sign(clecert_monitor.private_key, None, default_backend())
        clecert_monitor.csr = request

        return clecert_monitor

    def generer_clecert_module(self, role: str, common_name: str, nomcle: str = None, liste_dns: list = None, combiner_keycert=False) -> EnveloppeCleCert:
        clecert = self._renouvelleur.preparer_csr_par_role(role, common_name, liste_dns)

        # Post vers certissuer pour signer avec l'autorite, obtenir le certificat
        requete = {'csr': clecert.csr_bytes.decode('utf-8'), 'role': role, 'liste_dns': liste_dns}
        # Signer avec certificat de monitor pour autoriser le certissuer
        formatteur_message = self._service_monitor.get_formatteur_message(self.clecert_monitor)
        requete_signee, uuid_transaction = formatteur_message.signer_message(requete, 'certissuer', action="signer", ajouter_chaine_certs=True)

        url_certissuer = self.get_url_certissuer()
        url_certissuer = url_certissuer + '/certissuerInterne/signerModule'
        reponse = requests.post(url_certissuer, json=requete_signee, timeout=10)
        reponse.raise_for_status()
        reponse_json = reponse.json()
        chaine = reponse_json['certificat']
        clecert.chaine = chaine
        clecert.ca = reponse_json['ca']

        if nomcle is None:
            nomcle = role

        chaine_certs = '\n'.join(chaine)
        secret = clecert.private_key_bytes

        # Verifier si on doit combiner le cert et la cle (requis pour Mongo)
        if combiner_keycert or role in [ConstantesGenerateurCertificat.ROLE_MONGO, ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS]:
            secret_str = [str(secret, 'utf-8')]
            secret_str.extend(chaine)
            secret = '\n'.join(secret_str).encode('utf-8')

        labels = {'mg_type': 'pki', 'role': role, 'common_name': common_name}

        self.ajouter_secret('pki.%s.key' % nomcle, secret, labels=labels)
        self.ajouter_config('pki.%s.cert' % nomcle, chaine_certs.encode('utf-8'), labels=labels)

        # Conserver sur disque (au besoin, seulement si folder correspondant existe deja)
        self.sauvegarder_certificat_container('pki.%s.cert' % nomcle, clecert)

        return clecert

    def charger_certificats(self):
        secret_path = path.abspath(self.secret_path)
        os.makedirs(secret_path, exist_ok=True)  # Creer path secret, au besoin

        # Valider existence des certificats/chaines de base
        self._charger_certificat_docker('pki.millegrille.cert')

        try:
            # Charger information certificat monitor
            config_cert_monitor = self._service_monitor.gestionnaire_docker.trouver_config('pki.monitor.cert')
            cert_pem = self._charger_certificat_docker('pki.monitor.cert')
            if self._service_monitor.is_dev_mode:
                path_key = os.path.join(self._service_monitor.path_secrets,
                                        'pki.monitor.key.%s' % config_cert_monitor['date'])
            else:
                path_key = os.path.join(self._service_monitor.path_secrets, 'pki.monitor.key.pem')
            with open(path_key, 'rb') as fichiers:
                key_pem = fichiers.read()
            clecert_monitor = EnveloppeCleCert()
            clecert_monitor.from_pem_bytes(key_pem, cert_pem)
            self.clecert_monitor: EnveloppeCleCert = clecert_monitor

            # Conserver reference au cert monitor pour middleware
            self.certificats[GestionnaireCertificats.MONITOR_CERT_PATH] = self.certificats['pki.monitor.cert']
            self.certificats[GestionnaireCertificats.MONITOR_KEY_FILE] = GestionnaireCertificats.MONITOR_KEY_FILENAME + '.pem'

        except Exception:
            self.__logger.exception("Erreur chargement certificat monitor, il va etre regenere")

    def preparer_repertoires(self):
        mounts = path.join('/var/opt/millegrilles', self.idmg, 'mounts')
        os.makedirs(mounts, mode=0o770)

    def commande_signer_navigateur(self, commande):
        raise NotImplementedError("TODO")

    def commande_signer_noeud(self, commande):
        raise NotImplementedError("TODO")

    def renouveller_intermediaire(self, commande):
        raise NotImplementedError("TODO")


class GestionnaireCertificatsInstallation(GestionnaireCertificats):

    def __init__(self, docker_client: docker.DockerClient, service_monitor, **kwargs):
        super().__init__(docker_client, service_monitor, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def preparer_repertoires(self):
        mounts = path.join('/var/opt/millegrilles', self.idmg, 'mounts')
        os.makedirs(mounts, mode=0o770)

        if self._mode_insecure:
            try:
                os.mkdir('/var/opt/millegrilles/secrets', 0o755)
            except FileExistsError:
                pass

    # def signer_csr(self, csr: bytes):
    #     generateur = RenouvelleurCertificat(self.idmg, dict(), self._clecert_intermediaire, ca_autorite=self._clecert_millegrille)
    #
    #     duree_certs = environ.get('CERT_DUREE') or '3'  # Default 3 jours
    #     duree_certs = int(duree_certs)
    #
    #     duree_certs_heures = environ.get('CERT_DUREE_HEURES') or '0'  # Default 0 heures de plus
    #     duree_certs_heures = int(duree_certs_heures)
    #
    #     duree_intervalle = datetime.timedelta(days=duree_certs, hours=duree_certs_heures)
    #     clecert = generateur.signer_csr(csr, duree=duree_intervalle)
    #
    #     return clecert

    def generer_certificat_nginx_selfsigned(self, insecure=False):
        """
        Utilise pour genere un certificat self-signed initial pour nginx
        :return:
        """
        generateur = GenerateurCertificatNginxSelfsigned()

        clecert_ed25519 = generateur.generer('Installation')
        cle_pem_bytes_ed25519 = clecert_ed25519.private_key_bytes
        cert_pem_ed25519 = clecert_ed25519.public_bytes

        clecert_web = generateur.generer('Installation', rsa=True)
        cle_pem_web = clecert_web.private_key_bytes
        cert_pem_web = clecert_web.public_bytes

        # Certificat interne
        self.ajouter_secret('pki.nginx.key', data=cle_pem_bytes_ed25519)
        self.ajouter_config('pki.nginx.cert', data=cert_pem_ed25519)

        # Certificat web
        self.ajouter_secret('pki.web.key', data=cle_pem_web)
        self.ajouter_config('pki.web.cert', data=cert_pem_web)

        if insecure:  # Mode insecure
            key_path = path.join(self.secret_path, 'pki.nginx.key.pem')
            try:
                with open(key_path, 'xb') as fichier:
                    fichier.write(cle_pem_bytes_ed25519)
            except FileExistsError:
                pass

            key_path = path.join(self.secret_path, 'pki.web.key.pem')
            try:
                with open(key_path, 'xb') as fichier:
                    fichier.write(cle_pem_web)
            except FileExistsError:
                pass

        return clecert_ed25519

class ErreurSignatureCertificatException(Exception):
    pass
