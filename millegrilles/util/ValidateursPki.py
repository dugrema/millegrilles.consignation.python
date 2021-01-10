# Module de validation des certificats (X.509) et des messages avec _signature
import datetime

from typing import cast, Optional, Union
from cryptography.x509 import Certificate
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError, PathBuildingError

from millegrilles.SecuritePKI import EnveloppeCertificat


class ValidateurCertificat:

    def __init__(self, idmg: str, certificat_millegrille: Union[bytes, str, list] = None):
        self.__idmg = idmg

        # Validation context pour le idmg courant
        self.__validation_context: Optional[ValidationContext] = None

    def _charger_certificat(self, certificat: Union[bytes, str, list]) -> EnveloppeCertificat:
        if isinstance(certificat, bytes):
            certificat = EnveloppeCertificat(certificat_pem=certificat.decode('utf-8'))
        elif isinstance(certificat, str) or isinstance(certificat, list):
            certificat = EnveloppeCertificat(certificat_pem=certificat)
        else:
            raise TypeError("Type de certificat non supporte")

        return certificat

    def valider(
            self,
            certificat: Union[bytes, str, list],
            date_reference: datetime.datetime = None,
            idmg: str = None
    ) -> EnveloppeCertificat:
        """
        Valide un certificat. Conserve les certificats CA valides pour reutilisation/validation en memoire.
        :param certificat: Un certificat ou une liste de certificats a valider.
        :param date_reference: Date de reference pour valider le certificat si autre que date courante.
        :param idmg: IDMG de la millegrille a valider (si autre que la millegrille locale).
        :return:
        """
        enveloppe = self._charger_certificat(certificat)
        validation_context = self._preparer_validation_context(enveloppe, date_reference=date_reference, idmg=idmg)
        self.__run_validation_context(enveloppe, validation_context)

        return enveloppe

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

    def valider_x509_enveloppe(self, enveloppe: EnveloppeCertificat,
                               date_reference: datetime.datetime = None):
        """
        Valide une enveloppe
        :param enveloppe:
        :param date_reference:
        :param ignorer_date: Charger le certificat en utilisation date courante ou fin de periode de validite
        :return: Resultat de validation (toujours valide)
        :raises certvalidator.errors.PathBuildingError: Si le path est invalide
        """
        cert_pem = enveloppe.certificat_pem.encode('utf-8')
        inter_list = list()

        # self._logger.debug("CERT PEM :\n%s" % enveloppe.certificat_pem)
        for pem in enveloppe.reste_chaine_pem:
            # self._logger.debug("Chaine PEM :\n%s" % pem.strip())
            inter_list.append(pem.strip().encode('utf-8'))

        if date_reference is not None:
            # batir un contexte avec la date
            validation_context = ValidationContext(moment=date_reference, trust_roots=[self.__cert_millegrille])
        else:
            validation_context = self.__validation_context

        # Verifier le certificat - noter qu'une exception est lancee en cas de probleme
        try:
            validator = CertificateValidator(
                cert_pem, intermediate_certs=inter_list, validation_context=validation_context)
            resultat = validator.validate_usage({'digital_signature'})
            enveloppe.set_est_verifie(True)
        except PathValidationError as pve:
            msg = pve.args[0]
            if 'expired' in msg:
                self._logger.info("Un des certificats est expire, verifier en fonction de la date de reference")
                # Le certificat est expire, on fait la validation pour la fin de la periode de validite
                date_reference = pytz.UTC.localize(enveloppe.not_valid_after)
                validation_context = ValidationContext(moment=date_reference, trust_roots=[self.__cert_millegrille])
                validator = CertificateValidator(
                    cert_pem, intermediate_certs=inter_list, validation_context=validation_context)
                try:
                    resultat = validator.validate_usage({'digital_signature'})
                    enveloppe.set_est_verifie(True)
                    raise CertificatExpire()  # La chaine est valide pour une date anterieure
                except PathValidationError as pve:
                    if self._logger.isEnabledFor(logging.DEBUG):
                        self._logger.exception("Erreur validation path certificat")
                    else:
                        self._logger.info("Erreur validation path certificat : %s", str(pve))
            else:
                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.exception("Erreur validation path certificat")
                else:
                    self._logger.info("Erreur validation path certificat : %s", str(pve))
                raise pve

        except PathBuildingError as pbe:
            # Verifier si on a une millegrille tierce
            dernier_cert_pem = inter_list[-1]
            dernier_cert = EnveloppeCertificat(certificat_pem=dernier_cert_pem)
            if dernier_cert.is_rootCA:
                idmg = dernier_cert.idmg
                # Verifier si le idmg est dans la liste des idmg autorises
                autorisation = self.__autorisations_idmg.get(idmg)
                if autorisation is None:
                    # Pas autorise, lancer l'exception
                    raise pbe
                elif autorisation.get('domaines_permis'):
                    # Valider la chaine en fonction de la racine fournie
                    if date_reference is not None:
                        # batir un contexte avec la date
                        validation_context = ValidationContext(moment=date_reference,
                                                               trust_roots=[self.__cert_millegrille, dernier_cert_pem])
                    else:
                        validation_context = ValidationContext(trust_roots=[self.__cert_millegrille, dernier_cert_pem])

                    validator = CertificateValidator(
                        cert_pem, intermediate_certs=inter_list, validation_context=validation_context)

                    validator.validate_usage({'digital_signature'})

                    # Valide, on lance une exception pour indiquer la condition de validite (business rule)
                    raise AutorisationConditionnelleDomaine(autorisation['domaines_permis'], idmg, enveloppe)

        return resultat