"""
Gateway entre Blynk et SenseursPassifs de MilleGrilles
"""
import logging
import json

from blynklib import Blynk
from threading import Thread, Event
from typing import Optional

from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles import Constantes
from millegrilles.Constantes import SenseursPassifsConstantes


class ConstantesGatewayBlynk:
    pass


class GatewayBlynk:
    """
    Gestionnaire de gateway, supporte tous les noeuds prive configures pour Blynk
    """

    def __init__(self, contexte: ContexteRessourcesDocumentsMilleGrilles):
        self._contexte = contexte

        self.__channel = None

        self._blynk_devices = dict()
        self._senseur_devicevpin = dict()  # Mapping de cle:uuid_senseur vers le value:Device/VPIN correspondant

        self._traitement_messages = None

        self.__thread: Optional[Thread] = None
        self.__stop_event = Event()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def configurer(self):
        """
        Charger la configuration des noeuds prives/publics avec configuration Blynk
        :return:
        """
        collection = self._contexte.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)

        filtre_noeuds = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: SenseursPassifsConstantes.LIBVAL_DOCUMENT_NOEUD,
            Constantes.DOCUMENT_INFODOC_SECURITE: {'$in': [Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]}
        }
        noeuds = collection.find(filtre_noeuds)

        for noeud in noeuds:
            noeud_id = noeud['noeud_id']
            blynk_auth = noeud['blynk_auth']
            blynk_host = noeud['blynk_host']
            blynk_port = noeud['blynk_port']

            blynk = Blynk(
                blynk_auth, server=blynk_host, port=blynk_port,
                ssl_cert=self._contexte.configuration.mq_cafile,
                heartbeat=10, rcv_buffer=1024, log=self.__logger.debug
            )

            self._blynk_devices[noeud_id] = GatewayNoeud(blynk)

        # Charger les VPINs des senseurs
        filtre_senseurs = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: SenseursPassifsConstantes.LIBVAL_DOCUMENT_SENSEUR,
            Constantes.DOCUMENT_INFODOC_SECURITE: {'$in': [Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]},
            SenseursPassifsConstantes.TRANSACTION_NOEUD_ID: {'$in': list(self._blynk_devices.keys())}
        }
        senseurs_device = collection.find(filtre_senseurs)
        for doc_senseur in senseurs_device:
            for type_senseur, senseur in doc_senseur['senseurs'].items():
                if senseur.get('blynk_vpin'):
                    # C'est un senseur associe a un vpin, on fait le mapping
                    senseur_path = '/'.join([doc_senseur[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR], type_senseur])
                    vpin = senseur['blynk_vpin']
                    self.__logger.info("Blynk %s = vpin %d" % (senseur_path, vpin))
                    self._senseur_devicevpin[senseur_path] = vpin

                    noeud_id = doc_senseur[SenseursPassifsConstantes.TRANSACTION_NOEUD_ID]
                    blynk_device = self._blynk_devices[noeud_id]
                    blynk_device.enregistrer_read(vpin)

                    # Enregistrer derniere valeur dans le cache
                    valeur = senseur.get('valeur')
                    if valeur:
                        blynk_device.virtual_write(vpin, valeur)

        # Enregistrer MQ
        self._traitement_messages = TraitementMessages(self._contexte, self)

        routing = 'evenement.SenseursPassifs.#.lecture'

        self.contexte.message_dao.inscrire_topic(
            self.contexte.configuration.exchange_prive,
            [routing],
            self._traitement_messages.callbackAvecAck
        )

        # Tenter de s'inscrire a l'echange protege
        self.contexte.message_dao.inscrire_topic(
            self.contexte.configuration.exchange_protege,
            [routing],
            self._traitement_messages.callbackAvecAck
        )

    def start(self):
        """
        :return:
        """
        self.__thread = Thread(name="blynk", target=self.run)
        self.__thread.run()

    def fermer(self):
        self.__stop_event.set()

    def run(self):
        while not self.__stop_event.is_set():

            if len(self._blynk_devices) > 0:
                # Executer un cycle pour chaque device
                for noeud_id, blynk in self._blynk_devices.items():
                    try:
                        blynk.run()
                    except Exception:
                        self.__logger.exception("Erreur blynk noeud_id: %s" % noeud_id)
            else:
                self.__stop_event.wait(5)

        for noeud_id, blynk in self._blynk_devices.items():
            try:
                blynk.disconnect()
            except:
                self.__logger.info("Erreur dexonnexion %s" % noeud_id)

    def transmettre_lecture(self, noeud_id, uuid_senseur, type_senseur, valeur):
        cle = '/'.join([uuid_senseur, type_senseur])
        vpin = self._senseur_devicevpin.get(cle)
        if vpin:
            self.__logger.debug("Transmettre noeud: %s, vpin: %s, valeur: %s" % (noeud_id, vpin, valeur))
            blynk = self._blynk_devices.get(noeud_id)
            if blynk:
                blynk.virtual_write(vpin, valeur)

    @property
    def contexte(self):
        return self._contexte


class GatewayNoeud:
    """
    Gateway et connexion pour un device Blynk associe a un noeud prive MilleGrille
    """

    def __init__(self, blynk: Blynk):
        self._blynk = blynk

        self.__cache_valeurs = dict()

    def virtual_write(self, v_pin, val):
        self.__cache_valeurs[str(v_pin)] = val
        if self._blynk.connected():
            self._blynk.virtual_write(v_pin, val)

    def enregistrer_read(self, v_pin):
        blynk = self._blynk

        @blynk.handle_event('read V' + str(v_pin))
        def read_virtual_pin_handler(pin):
            valeur = self.__cache_valeurs[str(pin)]
            self._blynk.virtual_write(pin, valeur)

    def run(self):
        self._blynk.run()


class TraitementMessages(BaseCallback):
    """
    Recoit les messages d'evenements et changements de configuration SenseursPassifs
    """

    def __init__(self, contexte: ContexteRessourcesDocumentsMilleGrilles, gateway: GatewayBlynk):
        super().__init__(contexte)
        self._gateway = gateway

    def traiter_message(self, ch, method, properties, body):
        message_dict = json.loads(body.decode('utf-8'))

        uuid_senseur = message_dict.get(SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR)
        noeud_id = message_dict.get(SenseursPassifsConstantes.TRANSACTION_NOEUD_ID)
        senseurs = message_dict.get('senseurs')

        if uuid_senseur and noeud_id and senseurs:
            for type_senseur, senseur in senseurs.items():
                valeur = senseur.get('valeur')
                if valeur:
                    self._gateway.transmettre_lecture(noeud_id, uuid_senseur, type_senseur, valeur)
