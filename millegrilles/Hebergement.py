import logging
import tempfile
import os

from base64 import b64decode
from threading import Event, Thread

from millegrilles.util.UtilScriptLigneCommandeMessages import ModeleConfiguration
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesHebergement, ConstantesHebergementTransactions
from millegrilles.dao.MessageDAO import JSONHelper, BaseCallback, CertificatInconnu
from millegrilles.util.X509Certificate import EnveloppeCleCert
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.transaction.ConsignateurTransaction import ConsignateurTransaction


class ConfigurationHebergement(TransactionConfiguration):

    PROPERTIES_OVERRIDE = {
        Constantes.CONFIG_MQ_KEYFILE: '',
        Constantes.CONFIG_MQ_CERTFILE: '',
        Constantes.CONFIG_MQ_AUTH_CERT: '',
        Constantes.CONFIG_MQ_SSL: 'on',
        Constantes.CONFIG_MONGO_SSL: 'x509',
        Constantes.CONFIG_MONGO_AUTHSOURCE: '$external',
    }

    def __init__(self, configuration_hote: TransactionConfiguration, config_hebergement: dict):
        super().__init__()
        self.__configuration_hote = configuration_hote
        self.__config_hebergement = config_hebergement

        self.__parametres = dict()

        self.__temp_folder: str = None

        self.preparer_configuration_hebergement()
        self.preparer_fichiers()

    def preparer_configuration_hebergement(self):

        properties_override = ConfigurationHebergement.PROPERTIES_OVERRIDE.copy()

        configurations = [
            self.__configuration_hote._mq_config,
            self.__configuration_hote._mongo_config,
            self.__configuration_hote._millegrille_config,
            self.__configuration_hote._domaines_config,
            self.__configuration_hote._email_config,
            self.__configuration_hote._pki_config,
            self.__configuration_hote._serveurs,
            self.__configuration_hote._backup,
        ]

        for conf in configurations:
            for key, value in conf.items():
                override_value = properties_override.get(key)

                if override_value:
                    self.__parametres[key] = override_value
                else:
                    self.__parametres[key] = value

    def preparer_fichiers(self):
        # Creer nouveau repertoire temporaire pour fichiers

        self.__temp_folder = tempfile.mkdtemp(dir='/tmp')
        os.chmod(self.__temp_folder, mode=0o700)

        chaine_hote = '\n'.join(self.__config_hebergement['chaine_hote'])
        fp, fichier_chaine_hote = tempfile.mkstemp(suffix='.pem', dir=self.__temp_folder)
        os.write(fp, chaine_hote.encode('utf-8'))
        os.close(fp)

        chaine_cert = '\n'.join(self.__config_hebergement['chaine_cert'])
        fp, fichier_chaine_cert = tempfile.mkstemp(suffix='.pem', dir=self.__temp_folder)
        os.write(fp, chaine_cert.encode('utf-8'))
        os.close(fp)

        cert_millegrille = self.__config_hebergement['millegrille']
        fp, fichier_cert_millegrille = tempfile.mkstemp(suffix='.pem', dir=self.__temp_folder)
        os.write(fp, cert_millegrille.encode('utf-8'))
        os.close(fp)

        cle = self.__config_hebergement['cle']
        fp, fichier_cle = tempfile.mkstemp(suffix='.pem', dir=self.__temp_folder)
        os.write(fp, cle.encode('utf-8'))
        os.close(fp)

        self.__parametres[Constantes.CONFIG_MQ_CERTFILE] = fichier_chaine_hote
        self.__parametres[Constantes.CONFIG_MQ_KEYFILE] = fichier_cle
        # self.__parametres[Constantes.CONFIG_MQ_CA_CERTS] = fichier_cert_millegrille

        # Charger idmg a partir du certificat
        cert = self.__config_hebergement['chaine_hote'][0]
        clecert = EnveloppeCleCert()
        clecert.cert_from_pem_bytes(cert.encode('utf-8'))
        subject = clecert.formatter_subject()
        self.__parametres[Constantes.CONFIG_IDMG] = subject['organizationName']

    def find_value(self, dict_fichier_json, property):
        """
        :param dict_fichier_json:
        :param property:
        :return:
        """
        return self.__parametres.get(property)


class TraitementMessage(BaseCallback):

    def __init__(self, gestionnaire, contexte):
        super().__init__(contexte)
        self.__gestionnaire = gestionnaire
        self.__channel = None
        self.queue_name = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        correlation_id = properties.correlation_id
        exchange = method.exchange

        self.__logger.debug("Message recu : %s" % message_dict)

        if correlation_id == ConstantesHebergement.CORRELATION_MILLEGRILLES_ACTIVES:
            self.__gestionnaire.entretien_millegrilles_actives(message_dict['resultats'])
        elif correlation_id == ConstantesHebergement.CORRELATION_TROUSSEAU_MODULE:
            self.__gestionnaire.recevoir_trousseau(message_dict['resultats'])
        else:
            raise ValueError("Type message inconnu", correlation_id, routing_key)

    def on_channel_open(self, channel):
        self.__channel = channel
        channel.add_on_close_callback(self.__on_channel_close)
        channel.basic_qos(prefetch_count=1)

        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open)

    def queue_open(self, queue):
        self.queue_name = queue.method.queue
        self.__channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        self.__gestionnaire.queue_prete.set()

        # Ajouter les routing keys
        for rk in self.__gestionnaire.get_routing_keys:
            self.__channel.queue_bind(
                exchange=self.configuration.exchange_noeuds,
                queue=self.queue_name,
                routing_key=rk,
                callback=None
            )

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.queue_name = None

    def is_channel_open(self):
        return self.__channel is not None and not self.__channel.is_closed


class Hebergement(ModeleConfiguration):
    """
    Supporte la creation de Contexte pour une ou plusieurs MilleGrilles hebergees.
    """

    def __init__(self):
        super().__init__()
        self._millegrilles = dict()
        self.__fermeture_event = Event()
        self.__traitement_messages = None
        self.queue_prete = Event()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initialiser(self, init_document=True, init_message=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)
        self.__traitement_messages = TraitementMessage(self, self.contexte)
        self.contexte.message_dao.register_channel_listener(self.__traitement_messages)

    def deconnecter(self):
        self.__fermeture_event.set()

    def executer(self):
        self.__logger.info("Demarrage hebergement")

        self.queue_prete.wait(10)
        if self.queue_prete.is_set():
            self.__logger.info("Queue hebergement prete")

        while not self.__fermeture_event.is_set():
            self.verifier_millegrilles_actives()
            self.__fermeture_event.wait(10)

        self.__logger.info("Arret hebergement")

    def verifier_millegrilles_actives(self):
        """
        Transmet une requete pour demander la liste des MilleGrilles actives.
        :return:
        """
        domaine_requete = Constantes.ConstantesHebergement.REQUETE_MILLEGRILLES_ACTIVES
        queue_name = self.queue_name
        if not queue_name:
            raise ValueError("Queue reception non initialisee")

        self.contexte.generateur_transactions.transmettre_requete(
            {},
            domaine_requete,
            correlation_id=ConstantesHebergement.CORRELATION_MILLEGRILLES_ACTIVES,
            reply_to=self.queue_name
        )

    def entretien_millegrilles_actives(self, liste_millegrilles: list):

        for info in liste_millegrilles:
            idmg = info['idmg']
            self.__logger.debug("Entretien idmg %s", idmg)

            config_millegrille = self._millegrilles.get(idmg)
            if not config_millegrille:
                # Demarrer l'hebergement de la millegrille
                config_millegrille = info
                self._millegrilles[idmg] = config_millegrille
                self.demarrer_hebergement(idmg)
            else:
                # Entretien
                self.entretien_module(config_millegrille)

    def entretien_module(self, module: dict):
        raise NotImplementedError()

    def demarrer_hebergement(self, idmg):
        # Aller chercher le plus recent trousseau pour cette millegrille
        requete = {'idmg': [idmg]}
        domaine_requete = Constantes.ConstantesMaitreDesCles.DOMAINE_NOM + '.' + Constantes.ConstantesMaitreDesCles.REQUETE_TROUSSEAU_HEBERGEMENT
        self.contexte.generateur_transactions.transmettre_requete(
            requete,
            domaine_requete,
            correlation_id=ConstantesHebergement.CORRELATION_TROUSSEAU_MODULE,
            reply_to=self.queue_name,
        )

    def recevoir_trousseau(self, trousseaux: dict):
        for trousseau in trousseaux:
            idmg = trousseau[Constantes.CONFIG_IDMG]
            configuration = self._millegrilles[idmg]
            configuration[ConstantesHebergement.CORRELATION_TROUSSEAU_MODULE] = trousseau

            # Extraire cle-cert du trousseau
            certificat_pem = trousseau[Constantes.ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM].encode('utf-8')
            cle_pem = trousseau['cle'].encode('utf-8')
            motdepasse_chiffre = trousseau['motdepasse_chiffre']

            # Dechiffrer mot de passe, charger cle privee et certificat
            signateur = self.contexte.signateur_transactions
            motdepasse = signateur.dechiffrage_asymmetrique(motdepasse_chiffre.encode('utf-8'))

            clecert = EnveloppeCleCert()
            clecert.from_pem_bytes(cle_pem, certificat_pem, motdepasse)
            clecert.password = None

            configuration['clecert'] = clecert

            # Charger la chaine de certificats pour se connecter a l'hote
            certificat_pem_str = str(certificat_pem, 'utf-8')
            certificats = trousseau['certificats']
            chaine_hote = [
                certificat_pem_str,
                certificats['hebergement'],
                certificats['hote_pem'],
            ]
            chaine_cert = [
                certificat_pem_str,
                certificats['intermediaire'],
            ]

            configuration['chaine_hote'] = chaine_hote
            configuration['chaine_cert'] = chaine_cert
            configuration['millegrille'] = certificats['millegrille']
            configuration['cle'] = str(clecert.private_key_bytes, 'utf-8')

            commande_ajouter_compte = {
                'certificat': str(certificat_pem, 'utf-8'),
                'chaine': chaine_hote[1:],
            }
            self.contexte.generateur_transactions.transmettre_commande(
                commande_ajouter_compte,
                'commande.' + Constantes.ConstantesServiceMonitor.COMMANDE_AJOUTER_COMPTE,
                exchange=self.contexte.configuration.exchange_middleware,
            )

            # Sauvegarder les fichiers CA, chaine hote, cert et cle.
            self.demarrer_contexte(idmg)

    def demarrer_contexte(self, idmg: str):
        raise NotImplementedError()

    @property
    def queue_name(self):
        return self.__traitement_messages.queue_name

    @property
    def get_routing_keys(self):
        raise NotImplementedError()


class HebergementTransactions(Hebergement):

    def __init__(self):
        super().__init__()
        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def demarrer_contexte(self, idmg: str):
        configuration = self._millegrilles[idmg]
        configuration_contexte = ConfigurationHebergement(self.contexte.configuration, configuration)

        contexte_hebergement = ContexteRessourcesDocumentsMilleGrilles(configuration=configuration_contexte)
        configuration['contexte'] = contexte_hebergement

        contexte_hebergement.initialiser()

        # Demarrer le gestionnaire de transaction
        consignateur_transactions = ConsignateurTransaction()
        configuration['consignateur'] = consignateur_transactions

        consignateur_transactions.configurer_parser()
        consignateur_transactions.parse()

        # Bypass initialiser - utilise les parametres system
        consignateur_transactions.initialiser_2(contexte_hebergement)

        thread = Thread(target=consignateur_transactions.executer, name=idmg)
        configuration['thread'] = thread

        thread.start()

    def entretien_module(self, module: dict):
        pass

    @property
    def get_routing_keys(self):
        return [
            'commande.hebergement.transactions.#'
        ]


class HebergementDomaines(Hebergement):

    def __init__(self):
        super().__init__()
        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)


class HebergementMaitreDesCles(Hebergement):

    def __init__(self):
        super().__init__()
        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)
