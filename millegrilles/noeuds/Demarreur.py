# Module qui permet de demarrer les appareils sur un Raspberry Pi
import traceback
import argparse
import logging

from threading import Event

from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO, ExceptionConnectionFermee
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.domaines.SenseursPassifs import ProducteurTransactionSenseursPassifs

from millegrilles.util.Daemon import Daemon

logger = logging.getLogger(__name__)


class DemarreurNoeud(Daemon):

    def __init__(
            self,
            pidfile='/run/mg-demarreur-rpi.pid',
            stdin='/dev/null',
            stdout='/var/log/mg-demarreur-rpi.log',
            stderr='/var/log/mg-demarreur-rpi.err'
    ):
        # Call superclass init
        Daemon.__init__(self, pidfile, stdin, stdout, stderr)

        logging.getLogger().setLevel(logging.WARNING)
        logging.getLogger('millegrilles.noeuds').setLevel(logging.INFO)

        self._parser = argparse.ArgumentParser(description="Demarrer un noeud MilleGrilles")
        self._args = None

        self._intervalle_entretien = None
        self._max_backlog = None
        self._apcupsd = None

        self._configuration = TransactionConfiguration()
        self._message_dao = None
        self._document_dao = None
        self._producteur_transaction = None

        self._chargement_reussi = False  # Vrai si au moins un module a ete charge
        self._stop_event = Event()
        self._stop_event.set()  # Set initiale, faire clear pour activer le processus

        self._backlog_messages = []  # Utilise pour stocker les message qui n'ont pas ete transmis

    def print_help(self):
        self._parser.print_help()

    def parse(self):
        self._parser.add_argument(
            'command', type=str, nargs=1, choices=['start', 'stop', 'restart'],
            help="Commande a executer: start, stop, restart"
        )
        self._parser.add_argument(
            '--apcupsd', type=int, nargs=1, required=False,
            help="Active le module pour les UPS APC avec numero de senseur en parametre."
        )
        self._parser.add_argument(
            '--apcupsd_host', type=str, nargs=1, required=False,
            help="Host ou se trouver le serveur du UPS APC (apcupsd)."
        )
        self._parser.add_argument(
            '--apcupsd_port', type=int, nargs=1, required=False,
            help="Port du serveur UPS APC (apcupsd)."
        )
        self._parser.add_argument(
            '--maint', type=int, nargs=1, default=60,
            required=False, help="Change le nombre de secondes entre les verifications de connexions"
        )
        self._parser.add_argument(
            '--backlog', type=int, nargs=1, default=1000,
            required=False, help="Change le nombre messages maximum qui peuvent etre conserves dans le backlog"
        )
        self._parser.add_argument(
            '--noconnect', action="store_true", required=False,
            help="Effectue la connexion aux serveurs plus tard plutot qu'au demarrage."
        )

        self._args = self._parser.parse_args()

    def executer_daemon_command(self):
        daemon_command = self._args.command[0]
        if daemon_command == 'start':
            self.start()
        elif daemon_command == 'stop':
            self.stop()
        elif daemon_command == 'restart':
            self.restart()

    def start(self):
        Daemon.start(self)

    def stop(self):
        Daemon.stop(self)

    def restart(self):
        Daemon.restart(self)

    def run(self):
        print("Demarrage Daemon")
        self.setup_modules()

        if self._chargement_reussi:
            self._stop_event.clear()  # Permettre de bloquer sur le stop_event.

        while not self._stop_event.is_set():
            # Faire verifications de fonctionnement, watchdog, etc...
            try:
                self.traiter_backlog_messages()
            except Exception:
                logger.exception("Erreur traitement backlog de messages")

            self.verifier_connexion_document()

            # Sleep
            self._stop_event.wait(self._intervalle_entretien)
        print("Fin execution Daemon")

    def setup_modules(self):
        # Charger la configuration et les DAOs
        self._configuration.loadEnvironment()
        self._message_dao = PikaDAO(self._configuration)
        self._document_dao = MongoDAO(self._configuration)

        # Se connecter aux ressources
        if not self._args.noconnect:
            self._message_dao.connecter()
            self._document_dao.connecter()

        self._producteur_transaction = ProducteurTransactionSenseursPassifs(self._configuration, self._message_dao)

        # Verifier les parametres
        self._intervalle_entretien = self._args.maint
        self._max_backlog = self._args.backlog

        if self._args.lcddoc:
            try:
                self.inclure_lcd()
            except Exception as erreur_lcd:
                print("Erreur chargement ecran LCD: %s" % str(erreur_lcd))
                traceback.print_exc()

        if self._args.nrf24:
            try:
                self.inclure_nrf24l01()
            except Exception as erreur_nrf24:
                print("Erreur chargement hub nRF24L01: %s" % str(erreur_nrf24))
                traceback.print_exc()

        if self._args.am2302:
            try:
                self.inclure_am2302()
            except Exception as erreur_nrf24:
                print("Erreur chargement AM2302 sur pin %d: %s" % (self._args.am2302[1], str(erreur_nrf24)))
                traceback.print_exc()

    def fermer(self):
        self._stop_event.set()

        try:
            self._message_dao.deconnecter()
            self._document_dao.deconnecter()
        except Exception as edao:
            print("Erreur deconnexion DAOs: %s" % str(edao))

        if self._hub_nrf24l01 is not None:
            try:
                self._hub_nrf24l01.fermer()
            except Exception as enrf:
                print("erreur fermeture NRF24L01: %s" % str(enrf))

        if self._affichage_lcd is not None:
            try:
                self._affichage_lcd.fermer()
            except Exception as elcd:
                print("erreur fermeture LCD: %s" % str(elcd))

        if self._am2302 is not None:
            try:
                self._am2302.fermer()
            except Exception as eam:
                print("erreur fermeture AM2302: %s" % str(eam))

    def inclure_apcupsd(self):
        print("Activer apcupsd via nis")
        from millegrilles.noeuds.NRF24L import HubNRF24L
        self._hub_nrf24l01 = HubNRF24L()
        self._hub_nrf24l01.start(self.transmettre_lecture_callback)
        self._chargement_reussi = True

    def inclure_am2302(self):
        no_senseur = self._args.am2302[0]
        pin = self._args.am2302[1]
        print("Activer AS2302 sur pin %d" % pin)
        from mgraspberry.raspberrypi.AdafruitDHT import ThermometreAdafruitGPIO
        self._am2302 = ThermometreAdafruitGPIO(no_senseur=no_senseur, pin=pin)
        self._am2302.start(self.transmettre_lecture_callback)
        self._chargement_reussi = True

    def transmettre_lecture_callback(self, dict_lecture):
        try:
            if not self._message_dao.in_error:
                self._producteur_transaction.transmettre_lecture_senseur(dict_lecture)
            else:
                print("Message ajoute au backlog: %s" % str(dict_lecture))
                if len(self._backlog_messages) < 1000:
                    self._backlog_messages.append(dict_lecture)
                else:
                    print("Backlog > 1000, message perdu: %s" % str(dict_lecture))

        except ExceptionConnectionFermee as e:
            # Erreur, la connexion semble fermee. On va tenter une reconnexion
            self._backlog_messages.append(dict_lecture)
            self._message_dao.enter_error_state()

    ''' Verifie s'il y a un backlog, tente de reconnecter au message_dao et transmettre au besoin. '''
    def traiter_backlog_messages(self):
        if len(self._backlog_messages) > 0:
            # Tenter de reconnecter a RabbitMQ
            if self._message_dao.in_error:
                try:
                    self._message_dao.connecter()
                except:
                    logger.exception("Erreur connexion MQ")

            # La seule facon de confirmer la connexion et d'envoyer un message
            # On tente de passer le backlog en remettant le message dans la liste en cas d'echec
            message = self._backlog_messages.pop()
            try:
                self._producteur_transaction.transmettre_lecture_senseur(message)
                while len(self._backlog_messages) > 0:
                    message = self._backlog_messages.pop()
                    self._producteur_transaction.transmettre_lecture_senseur(message)
                print("Traitement backlog complete")
            except Exception as e:
                print("Erreur traitement backlog, on push le message: %s" % str(e))
                self._backlog_messages.append(message)
                traceback.print_exc()

    ''' Verifie la connexion au document_dao, reconnecte au besoin. '''
    def verifier_connexion_document(self):
        if not self._document_dao.est_enligne():
            try:
                self._document_dao.connecter()
                print("DemarreurRaspberryPi: Connexion a Mongo re-etablie")
            except Exception as ce:
                print("DemarreurRaspberryPi: Erreur reconnexion Mongo: %s" % str(ce))
                traceback.print_exc()


# **** MAIN ****
def main():
    try:
        demarreur.parse()
        demarreur.executer_daemon_command()
    except Exception as e:
        print("!!! ******************************")
        print("MAIN: Erreur %s" % str(e))
        traceback.print_exc()
        print("!!! ******************************")
        demarreur.print_help()


if __name__ == "__main__":
    demarreur = DemarreurRaspberryPi()
    main()
