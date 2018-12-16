# Module qui s'occupe des emails dans MilleGrilles
import smtplib
from email.message import EmailMessage


class SmtpDAO:

    def __init__(self, configuration):
        self._configuration = configuration

    def envoyer_notification(self, sujet, contenu):
        # Verification que les parametres sont fournis
        if self._configuration.email_password is None:
            raise ValueError("Erreur configuration SMTP, le mot de passe n'a pas ete fourni")

        msg = EmailMessage()
        msg.set_content(contenu)
        msg['Subject'] = sujet

        msg['From'] = self._configuration.email_from
        msg['To'] = self._configuration.email_to

        s = smtplib.SMTP_SSL(self._configuration.email_host, self._configuration.email_port)
        s.login(self._configuration.email_user, self._configuration.email_password)

        s.send_message(msg)
        s.quit()
