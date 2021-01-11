# Module de validation des certificats (X.509) et des messages avec _signature
import datetime
import logging
import json

from typing import Optional, Union, Dict
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError
from threading import Event, Barrier

from millegrilles.Constantes import ConstantesPki, ConstantesSecurityPki
from millegrilles.SecuritePKI import EnveloppeCertificat, CertificatInconnu
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import ConnexionWrapper, BaseCallback


class ValidateurCertificat:
    """
    Validateur de base. Supporte uniquement la validation de chaine de certificats completes (en parametre).
    """

    def __init__(self, idmg: str, certificat_millegrille: Union[bytes, str, list] = None):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__idmg = idmg

        # Validation context pour le idmg courant
        self.__validation_context: Optional[ValidationContext] = None

        if certificat_millegrille is not None:
            enveloppe = self._charger_certificat(certificat_millegrille)
            if enveloppe.idmg != idmg:
                raise ValueError("Le certificat en parametre ne correspond pas au idmg %s" % idmg)
            certificat_millegrille_pem = enveloppe.certificat_pem
            self.__validation_context = ValidationContext(trust_roots=[certificat_millegrille_pem.encode('utf-8')])

    def _charger_certificat(self, certificat: Union[bytes, str, list]) -> EnveloppeCertificat:
        if isinstance(certificat, bytes):
            certificat = EnveloppeCertificat(certificat_pem=certificat.decode('utf-8'))
        elif isinstance(certificat, str) or isinstance(certificat, list):
            certificat = EnveloppeCertificat(certificat_pem=certificat)
        else:
            raise TypeError("Type de certificat non supporte")

        return certificat

    def _preparer_validation_context(
            self, enveloppe: EnveloppeCertificat, date_reference: datetime.datetime = None, idmg: str = None
    ) -> ValidationContext:
        if enveloppe.reste_chaine_pem is not None:
            # L'enveloppe a deja la chaine complete, on fait juste la passer au validateur
            validation_context = self.__preparer_validation_context(enveloppe, date_reference, idmg)
        else:
            raise PathValidationError("Impossible de preparer la chaine de validation du certificat (chaine manquante)")
        return validation_context

    def __preparer_validation_context(
            self, enveloppe: EnveloppeCertificat, date_reference: datetime.datetime = None, idmg: str = None
    ) -> ValidationContext:

        # Raccourci - si on a idmg et date par defaut et un validator deja construit
        if self.__validation_context is not None and date_reference is None and idmg is None:
            return self.__validation_context

        # Extraire le certificat de millegrille, verifier le idmg et construire le contexte
        idmg_effectif = idmg or self.__idmg
        certificat_millegrille_pem = enveloppe.reste_chaine_pem[-1]
        certificat_millegrille = EnveloppeCertificat(certificat_pem=certificat_millegrille_pem)
        if certificat_millegrille.idmg != idmg_effectif:
            raise ValueError("Certificat de millegrille ne correspond pas au idmg: %s" % idmg_effectif)

        if date_reference is not None:
            validation_context = ValidationContext(
                moment=date_reference,
                trust_roots=[certificat_millegrille_pem.encode('utf-8')]
            )
        else:
            validation_context = ValidationContext(trust_roots=[certificat_millegrille_pem.encode('utf-8')])

            if idmg_effectif == self.__idmg and self.__validation_context is None:
                # Conserver l'instance du validation context pour reutilisation
                self.__logger.debug("Conserver instance pour validation de certificat idmg = %s" % idmg_effectif)
                self.__validation_context = validation_context

        return validation_context

    def __run_validation_context(self, enveloppe: EnveloppeCertificat, validation_context: ValidationContext):
        cert_pem = enveloppe.certificat_pem.encode('utf-8')
        inter_list = [c.encode('utf-8') for c in enveloppe.reste_chaine_pem]
        validator = CertificateValidator(
            cert_pem,
            intermediate_certs=inter_list,
            validation_context=validation_context
        )
        validator.validate_usage({'digital_signature'})

    def valider(
            self,
            certificat: Union[bytes, str, list],
            date_reference: datetime.datetime = None,
            idmg: str = None
    ) -> EnveloppeCertificat:
        """
        Valide un certificat.

        :param certificat: Un certificat ou une liste de certificats a valider.
        :param date_reference: Date de reference pour valider le certificat si autre que date courante.
        :param idmg: IDMG de la millegrille a valider (si autre que la millegrille locale).

        :return: Enveloppe avec le certificat valide.
        :raise PathValidationError: Si la chaine de certificat est invalide.
        """
        enveloppe = self._charger_certificat(certificat)

        try:
            if enveloppe.est_verifie and date_reference is None and (idmg is None or idmg == self.__idmg):
                # Raccourci, l'enveloppe a deja ete validee (e.g. cache) et on n'a aucune
                # validation conditionnelle par date ou idmg
                return enveloppe
        except AttributeError:
            pass  # Ok, le certificat n'est pas connu ou dans le cache

        validation_context = self._preparer_validation_context(enveloppe, date_reference=date_reference, idmg=idmg)
        self.__run_validation_context(enveloppe, validation_context)

        # Validation completee, certificat est valide (sinon PathValidationError est lancee)
        enveloppe.set_est_verifie(True)

        # Le certificat est valide - on permet de le conserver si applicable (aucune validation conditionnelle)
        if date_reference is None and (idmg is None or idmg == self.__idmg):
            self._conserver_enveloppe(enveloppe)

        return enveloppe

    def _conserver_enveloppe(self, enveloppe: EnveloppeCertificat):
        """
        Hook pour sous-classes (e.g. caching)
        :param enveloppe:
        :return:
        """
        pass


class ValidateurCertificatCache(ValidateurCertificat):
    """
    Supporte un cache de certificats pour accelerer le traitement.
    """

    def __init__(self, idmg: str, certificat_millegrille: Union[bytes, str, list] = None):
        super().__init__(idmg, certificat_millegrille)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__enveloppe_leaf_par_fingerprint: Dict[str, EntreeCacheEnveloppe] = dict()

    def _conserver_enveloppe(self, enveloppe: EnveloppeCertificat):
        """
        Ajoute l'enveloppe dans le cache.
        :param enveloppe:
        :return:
        """
        if not enveloppe.est_verifie:
            raise ValueError("Certificat non verifie - Le cache ne fonctionne que sur des enveloppes verifiees")

        # Verifier si le certificat est deja dans le cache
        fingerprint = 'sha256_b64:' + enveloppe.fingerprint_sha256_b64
        if self.__enveloppe_leaf_par_fingerprint.get(fingerprint) is None:
            # S'assurer qu'on n'a pas deja depasse le nombre limite du cache
            if len(self.__enveloppe_leaf_par_fingerprint) > self.limite_obj_cache:
                self.entretien()

            # Conserver le certificat dans le cache
            self.__logger.debug("Cache certificat %s" % fingerprint)
            self.__enveloppe_leaf_par_fingerprint[fingerprint] = EntreeCacheEnveloppe(enveloppe)

            # Conserver toute la chaine - les certs CA sont deja valides
            chaine = enveloppe.reste_chaine_pem
            for i in range(0, len(chaine)):
                enveloppe_ca = EnveloppeCertificat(certificat_pem=chaine)
                chaine = chaine[1:]
                if enveloppe_ca.is_CA:
                    enveloppe_ca.set_est_verifie(True)
                    fingerprint_ca = enveloppe_ca.fingerprint_sha256_b64
                    if self.__enveloppe_leaf_par_fingerprint.get(fingerprint_ca) is None:
                        self.__enveloppe_leaf_par_fingerprint[fingerprint_ca] = EntreeCacheEnveloppe(enveloppe_ca)

        super()._conserver_enveloppe(enveloppe)

    def get_enveloppe(self, fingerprint: str):
        """
        :param fingerprint: Fingerprint du certificat
        :return: Enveloppe du certificat avec la chaine complete (si presente dans le cache). Sinon retourne None.
        """
        entree_cache = self.__enveloppe_leaf_par_fingerprint.get(fingerprint)
        try:
            return entree_cache.enveloppe
        except AttributeError:
            # Entree inexistante
            return None

    def entretien(self):
        """
        Invoquer regulirement pour faire l'entretien du cache (eliminer entrees trop vieilles).
        :return:
        """
        # Eliminer les certificats non CA qui sont expires
        expiration = datetime.datetime.utcnow() - self.expiration_cache
        for fingerprint, entry in self.__enveloppe_leaf_par_fingerprint.copy().items():
            envelopppe = entry.enveloppe
            if not envelopppe.is_CA and entry.dernier_acces < expiration:
                del self.__enveloppe_leaf_par_fingerprint[fingerprint]

        # Trier les certificats en ordre - CA preferes
        sorted_entries = sorted(self.__enveloppe_leaf_par_fingerprint.values(), key=EntreeCacheEnveloppe.sort_key)
        supprimer = sorted_entries[self.max_entries_apres_nettoyage:]
        for e in supprimer:
            fingerprint = e.enveloppe.fingerprint_sha256_b64
            del self.__enveloppe_leaf_par_fingerprint[fingerprint]

    def _charger_certificat(self, certificat: Union[bytes, str, list]) -> EnveloppeCertificat:
        enveloppe = super()._charger_certificat(certificat)

        # Tenter de charger l'enveloppe a partir du cache - elle serait deja verifiee
        fingerprint = enveloppe.fingerprint_sha256_b64
        entree_cache = self.__enveloppe_leaf_par_fingerprint.get(fingerprint)
        try:
            enveloppe_verifiee = entree_cache.enveloppe  # self.get_enveloppe(fingerprint)
            if enveloppe_verifiee.est_verifie:
                return enveloppe_verifiee
        except AttributeError:
            pass  # OK

        # On n'a pas d'enveloppe verifiee
        return enveloppe

    @property
    def limite_obj_cache(self) -> int:
        """
        :return: Nombre maximum d'enveloppes dans le cache avant de forcer une purge
        """
        return 150

    @property
    def max_entries_apres_nettoyage(self) -> int:
        """
        :return: Nombre d'objets total conserves apres une purge certs (inclus root, CA et leaf)
        """
        return 100

    @property
    def expiration_cache(self) -> datetime.timedelta:
        """
        :return: Timedelta avant purge d'un certificat non CA dans le cache
        """
        return datetime.timedelta(minutes=15)


class ValidateurCertificatRequete(ValidateurCertificatCache):
    """
    Validateur qui tente de charger les certificats par fingerprint lorsqu'ils ne sont
    pas fournis explicitement ou dans le cache.
    """

    def __init__(self, contexte: ContexteRessourcesMilleGrilles, idmg: str, certificat_millegrille: Union[bytes, str, list] = None):
        super().__init__(idmg, certificat_millegrille)
        self.__contexte = contexte
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler = ReponseCertificatHandler(contexte, self)
        self.ready_event = Event()
        self.__stop_event = Event()

        self.__connexion_wrapper = ConnexionWrapper(contexte.configuration, self.__stop_event)
        self.__connexion_wrapper.register_channel_listener(self)

        self.channel = None
        self.queue_name: Optional[str] = None

        self.__attente: Dict[str, HandlerReponse] = dict()

        self.__barrier_connexion = Barrier(2)

    def fermer(self):
        self.__stop_event.set()

    def connecter(self):
        self.__connexion_wrapper.connecter(self.__barrier_connexion)
        self.__barrier_connexion.wait(5)

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open)

    def queue_open(self, queue):
        self.queue_name = queue.method.queue
        self.__logger.info("Queue: %s" % self.queue_name)
        self.channel.basic_consume(self.__handler.callbackAvecAck, queue=self.queue_name, no_ack=False)

    def get_enveloppe(self, fingerprint: str):

        # Tenter de charger le certificat a partir du cache
        enveloppe = super().get_enveloppe(fingerprint)

        if enveloppe is None:
            # Le certificat n'est pas dans le cache, tenter de faire une requete via MQ
            domaine_action = 'requete.Pki.' + ConstantesPki.REQUETE_CERTIFICAT
            requete = {
                'fingerprint': fingerprint
            }

            try:
                # Verifier si un handler existe deja pour le meme certificat
                handler_reponse = self.__attente[fingerprint]
                event_attente = handler_reponse.event
            except KeyError:
                # Handler n'existe pas
                event_attente = Event()
                handler_reponse = HandlerReponse(event_attente, timestamp=datetime.datetime.utcnow(), fingerprint=fingerprint)
                self.__attente[fingerprint] = handler_reponse

            # Note : on transmet potentiellement la requete pour le meme certificat plusieurs fois
            self.__contexte.generateur_transactions.transmettre_requete(
                requete, domaine_action, correlation_id=fingerprint, reply_to=self.queue_name
            )

            event_attente.wait(5)  # Timeout apres 5 secondes

            try:
                del self.__attente[fingerprint]
            except Exception:
                pass  # OK

            try:
                # Preparer chaine de certificats
                message = handler_reponse.message
                pems = [message['certificats_pem'][fp] for fp in message['chaine']]
                enveloppe = EnveloppeCertificat(certificat_pem=pems)
            except TypeError:
                pass  # OK, certificat pas recu

        return enveloppe

    def valider_fingerprint(
            self,
            fingerprint: str,
            date_reference: datetime.datetime = None,
            idmg: str = None
    ) -> EnveloppeCertificat:

        enveloppe = self.get_enveloppe(fingerprint)
        try:
            if enveloppe.est_verifie:
                return enveloppe
            else:
                chaine = [enveloppe.certificat_pem]
                chaine.extend(enveloppe.reste_chaine_pem)
                enveloppe = self.valider(chaine, date_reference, idmg)
                return enveloppe
        except AttributeError:
            # Le certificat n'est pas trouve
            raise CertificatInconnu('Certificat inconnu ' + fingerprint, fingerprint=fingerprint)

    def recevoir_reponse(self, message: dict):
        fingerprint = 'sha256_b64:' + message.get(ConstantesSecurityPki.LIBELLE_FINGERPRINT_SHA256_B64)
        handler_attente = self.__attente.get(fingerprint)

        try:
            handler_attente.message = message
        except AttributeError:
            # Reponse ne correspond a aucun certificat en attente
            self.__logger.warning("Message recu pour fingerprint %s, aucun handler en attente" % fingerprint)
        else:
            handler_attente.set_event()  # Declencher traitement de la reponse

    def entretien(self):
        super().entretien()

        expire = datetime.datetime.utcnow() - self.expiration_attente
        for key, handler in self.__attente.copy().items():
            if handler.timestamp < expire:
                self.__logger.warning("Nettoyage handler attente certificat stale : %s" % key)
                del self.__attente[key]

    @property
    def expiration_attente(self) -> datetime.timedelta:
        """
        :return: Timedelta avant purge des handlers en attente
        """
        return datetime.timedelta(seconds=15)


class ReponseCertificatHandler(BaseCallback):

    def __init__(self, contexte: ContexteRessourcesMilleGrilles, validateur: ValidateurCertificatRequete):
        super().__init__(contexte)
        self.__validateur = validateur
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def traiter_message(self, ch, method, properties, body):

        try:
            # Extraire contenu json. Noter qu'on ne valide pas le message, les certificats sont auto-validants.
            message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

            if self.__logger.isEnabledFor(logging.DEBUG):
                json_body = json.dumps(message_dict, indent=2)
                self.__logger.debug("ReponseCertificatHandler: %s\n%s" % (properties.correlation_id, json_body))

            self.__validateur.recevoir_reponse(message_dict)
        except Exception:
            self.__logger.exception("Erreur traitement message reception certificat")


class EntreeCacheEnveloppe:

    def __init__(self, enveloppe: EnveloppeCertificat):
        self.__enveloppe = enveloppe
        self.__dernier_acces = datetime.datetime.utcnow()
        self.__nombre_acces = 0

    @property
    def enveloppe(self) -> EnveloppeCertificat:
        self.__dernier_acces = datetime.datetime.utcnow()  # Touch
        self.__nombre_acces += 1
        return self.__enveloppe

    @property
    def nombre_access(self):
        return self.__nombre_acces

    @property
    def dernier_acces(self) -> datetime.datetime:
        return self.__dernier_acces

    @staticmethod
    def sort_key(e) -> tuple:
        enveloppe: EnveloppeCertificat = e.enveloppe
        # Note : pour bool, utilier not pour faire montre en premier (false < true)
        return (
            not enveloppe.is_rootCA,
            not enveloppe.is_CA,
            e.nombre_access,
            e.dernier_acces
        )


class HandlerReponse:

    def __init__(self, event: Event, timestamp: datetime.datetime, fingerprint: str):
        self.__event = event
        self.__timestamp = timestamp
        self.__fingerprint = fingerprint
        self.message: Optional[dict] = None

    def set_event(self):
        self.__event.set()

    @property
    def event(self):
        return self.__event

    @property
    def timestamp(self) -> datetime.datetime:
        return self.__timestamp

    @property
    def fingerprint(self):
        return self.__fingerprint
