# Module de validation des certificats (X.509) et des messages avec _signature
import datetime
import logging

from typing import Optional, Union, Dict
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError

from millegrilles.SecuritePKI import EnveloppeCertificat


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
        fingerprint = enveloppe.fingerprint_sha256_b64
        if self.__enveloppe_leaf_par_fingerprint.get(fingerprint) is None:
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
        pass

    def _charger_certificat(self, certificat: Union[bytes, str, list]) -> EnveloppeCertificat:
        enveloppe = super()._charger_certificat(certificat)

        # Tenter de charger l'enveloppe a partir du cache - elle serait deja verifiee
        fingerprint = enveloppe.fingerprint_sha256_b64
        enveloppe_verifiee = self.get_enveloppe(fingerprint)

        if enveloppe_verifiee:
            return enveloppe_verifiee

        # On n'a pas d'enveloppe verifiee
        return enveloppe

    @property
    def limite_obj_cache(self) -> int:
        """
        :return: Nombre maximum d'enveloppes dans le cache avant de forcer une purge
        """
        return 100

    @property
    def expiration_cache(self) -> datetime.timedelta:
        """
        :return: Timedelta avant purge des certificats dans le cache
        """
        return datetime.timedelta(minutes=15)


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
    def dernier_acces(self) -> datetime.datetime:
        return self.__dernier_acces
