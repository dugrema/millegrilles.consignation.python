#!/usr/bin/python3

# Module qui permet de demarrer les appareils sur un Raspberry Pi
import traceback
import argparse
import logging
import random
import socket
import sys
import datetime
import os
import json
import lzma

from threading import Event, Thread
from typing import Optional

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import ExceptionConnectionFermee, BaseCallback
from millegrilles import Constantes
from millegrilles.Constantes import SenseursPassifsConstantes
from millegrilles.SecuritePKI import GestionnaireEvenementsCertificat
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction


from millegrilles.util.Daemon import Daemon


FORMAT_TIMESTAMP_FICHIER = '%Y%m%d%H%M'


class DemarreurNoeud(Daemon):

    def __init__(
            self,
            pidfile='/run/mg-noeud.pid',
            stdin='/dev/null',
            stdout='/var/log/mg-noeud.log',
            stderr='/var/log/mg-noeud.err'
    ):
        # Call superclass init
        Daemon.__init__(self, pidfile, stdin, stdout, stderr)

        logging.basicConfig(format=Constantes.LOGGING_FORMAT, level=logging.DEBUG)
        logging.getLogger().setLevel(logging.WARNING)
        logging.getLogger('millegrilles.noeuds').setLevel(logging.INFO)

        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._logger.info("Service %s" % self.__class__.__name__)

        self._parser = argparse.ArgumentParser(description="Demarrer un noeud MilleGrilles")
        self._args = None

        self._intervalle_entretien = None
        self._max_backlog = None
        self._apcupsd = None
        self._dummysenseurs = None

        self._contexte = ContexteRessourcesMilleGrilles()
        self._producteur_transaction: Optional[ProducteurTransactionSenseursPassifs] = None
        self.__certificat_event_handler = GestionnaireEvenementsCertificat(self._contexte)
        self.__channel = None

        self._chargement_reussi = False  # Vrai si au moins un module a ete charge
        self._stop_event = Event()
        self._stop_event.set()  # Set initiale, faire clear pour activer le processus

        self._message_handler: Optional[MessageCallback] = None
        self._backlog_messages = []  # Utilise pour stocker les message qui n'ont pas ete transmis

        self._thread_transactions: Optional[Thread] = None  # Thread de traitement du buffer, tranmission de transactions

    def print_help(self):
        self._parser.print_help()

    def parse(self):
        self._parser.add_argument(
            'command', type=str, nargs=1, choices=['start', 'stop', 'restart', 'nofork'],
            help="Commande a executer: start, stop, restart, nofork"
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
            '--apcupsd_pipe', type=str, nargs=1, required=False,
            help="Path pour le pipe d'evenements pour les scripts apcupsd."
        )
        self._parser.add_argument(
            '--data', type=str, nargs=1, required=False, default="/var/opt/millegrilles/data",
            help="Path du journal des transactions, buffer evenements"
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
        self._parser.add_argument(
            '--dummysenseurs', action="store_true", required=False,
            help="Initalise un emetteur de lecture dummy, pour tester la connexion"
        )
        self._parser.add_argument(
            '--debug', action="store_true", required=False,
            help="Active le logging maximal"
        )
        self._args = self._parser.parse_args()

    def executer_daemon_command(self):
        
        if self._args.debug:
            logging.getLogger('millegrilles').setLevel(logging.DEBUG)
        
        daemon_command = self._args.command[0]
        if daemon_command == 'start':
            self.start()
        elif daemon_command == 'stop':
            self.stop()
        elif daemon_command == 'restart':
            self.restart()
        elif daemon_command == 'nofork':
            # Executer sans fork
            self.run()

    def start(self):
        Daemon.start(self)

    def stop(self):
        Daemon.stop(self)
        self._stop_event.set()

    def restart(self):
        Daemon.restart(self)

    def on_channel_open(self, channel):
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)
        self.__channel = channel
        self.__certificat_event_handler.initialiser()

        self._message_handler = MessageCallback(self.contexte, self)
        # self.contexte.message_dao.enregistrer_callback(queue='', callback=self._message_handler.callbackAvecAck)
        self.contexte.message_dao.inscrire_topic(
            self.contexte.configuration.exchange_defaut,
            ['ceduleur.#'],
            self._message_handler.callbackAvecAck
        )

    def on_channel_close(self):
        self.__channel = None
        self._logger.info("MQ Channel ferme")
        if not self._stop_event:
            self._contexte.message_dao.enter_error_state()

    def run(self):
        self._logger.info("Demarrage Daemon")
        self.setup_modules()

        if self._chargement_reussi:
            self._stop_event.clear()  # Permettre de bloquer sur le stop_event.

        while not self._stop_event.is_set():
            # Faire verifications de fonctionnement, watchdog, etc...
            try:
                self.traiter_backlog_messages()
            except Exception:
                self._logger.exception("Erreur traitement backlog de messages")

            # Sleep
            self._stop_event.wait(self._intervalle_entretien)
        self._logger.info("Fin execution Daemon")

    def setup_modules(self):
        # Charger la configuration et les DAOs
        self._logger.info("Setup modules")
        doit_connecter = not self._args.noconnect
        self._contexte.initialiser(connecter=doit_connecter)
        self._contexte.message_dao.register_channel_listener(self)

        self._producteur_transaction = ProducteurTransactionSenseursPassifs(self._contexte, data_path=self._args.data)

        # Verifier les parametres
        self._intervalle_entretien = self._args.maint
        self._max_backlog = self._args.backlog

        if self._args.apcupsd:
            try:
                self.inclure_apcupsd()
            except Exception as erreur_lcd:
                self._logger.exception("Erreur chargement apcupsd: %s" % str(erreur_lcd))
                traceback.print_exc()

        if self._args.dummysenseurs:
            self.inclure_dummysenseurs()

    def fermer(self):
        self._stop_event.set()

        try:
            self.contexte.message_dao.deconnecter()
        except Exception as edao:
            self._logger.info("Erreur deconnexion DAOs: %s" % str(edao))

        if self._apcupsd is not None:
            try:
                self._apcupsd.fermer()
            except Exception as enrf:
                self._logger.info("erreur fermeture apcupsd: %s" % str(enrf))

    def inclure_apcupsd(self):
        self._logger.info("Activer apcupsd via nis")
        from millegrilles.noeuds.Apcups import ApcupsdCollector
        no_senseur = self._args.apcupsd[0]
        config = {}
        if self._args.apcupsd_host:
            config['hostname'] = self._args.apcupsd_host[0]
        if self._args.apcupsd_port:
            config['port'] = self._args.apcupsd_port[0]
        if self._args.apcupsd_pipe:
            config['pipe_path'] = self._args.apcupsd_pipe[0]
        self._logger.info("Configuration apcupsd: %s" % config)
        self._apcupsd = ApcupsdCollector(no_senseur=no_senseur, config=config)
        self._apcupsd.start(self.transmettre_lecture_callback)
        self._chargement_reussi = True

    def inclure_dummysenseurs(self):
        self._logger.info("Activer dummysenseurs")
        self._dummysenseurs = DummySenseurs(no_senseur="7a2764fa-c457-4f25-af0d-0fc915439b21")
        self._dummysenseurs.start(self.transmettre_lecture_callback)
        self._chargement_reussi = True

    def transmettre_lecture_callback(self, dict_lecture):
        try:
            if not self.contexte.message_dao.in_error:
                self._producteur_transaction.transmettre_lecture_senseur(dict_lecture, version=5)
            else:
                self._logger.info("Message ajoute au backlog: %s" % str(dict_lecture))
                if len(self._backlog_messages) < self._max_backlog:
                    self._backlog_messages.append(dict_lecture)
                else:
                    self._logger.warning("Backlog > 1000, message perdu: %s" % str(dict_lecture))

        except ExceptionConnectionFermee as e:
            # Erreur, la connexion semble fermee. On va tenter une reconnexion
            self._backlog_messages.append(dict_lecture)
            self.contexte.message_dao.enter_error_state()

    def produire_transactions(self):
        if not self._thread_transactions or not self._thread_transactions.is_alive():
            # Demarrer une thread pour produire les fichiers de transactions et les soumettre
            self._thread_transactions = Thread(
                name="transactions", target=self._producteur_transaction.generer_transactions)
            self._thread_transactions.start()

    ''' Verifie s'il y a un backlog, tente de reconnecter au message_dao et transmettre au besoin. '''
    def traiter_backlog_messages(self):
        if len(self._backlog_messages) > 0:
            # Tenter de reconnecter a RabbitMQ
            # if self.contexte.message_dao.in_error:
            #     try:
            #         self.contexte.message_dao.connecter()
            #     except:
            #         self._logger.exception("Erreur connexion MQ")

            # La seule facon de confirmer la connexion et d'envoyer un message
            # On tente de passer le backlog en remettant le message dans la liste en cas d'echec
            message = self._backlog_messages[0]  # Tenter transmettre un message, mais le garder en cas d'echec
            try:
                self._producteur_transaction.transmettre_lecture_senseur(message)
                # Succes (pas d'exception lancee), on enleve le premier message du backlog
                self._backlog_messages.pop()

                # Transmettre le reste des messages
                while len(self._backlog_messages) > 0:
                    message = self._backlog_messages.pop()
                    self._producteur_transaction.transmettre_lecture_senseur(message)
                self._logger.info("Traitement backlog complete")
            except Exception as e:
                self._logger.warning("Erreur traitement backlog, on push le message: %s" % str(e))
                self._backlog_messages.append(message)
                traceback.print_exc()

    @property
    def contexte(self):
        return self._contexte


# Thermometre AM2302 connecte sur une pin GPIO
# Dependances:
#   - Adafruit package Adafruit_DHT
class DummySenseurs:

    def __init__(self, no_senseur, intervalle_lectures=5):
        self._no_senseur = no_senseur
        self._intervalle_lectures = intervalle_lectures
        self._callback_soumettre = None
        self._stop_event = Event()
        self._thread = None

        self._stop_event.set()
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def lire(self):
        humidite = random.randrange(0, 1000) / 10
        temperature = random.randrange(-500, 500) / 10

        dict_message = {
            'uuid_senseur': self._no_senseur,
            'timestamp': int(datetime.datetime.now().timestamp()),
            'senseurs': [{
                'type': 'am2302',
                'temperature': round(temperature, 1),
                'humidite': round(humidite, 1)
            }]
        }

        self._callback_soumettre(dict_message)

    def start(self, callback_soumettre):
        self._callback_soumettre = callback_soumettre
        self._stop_event.clear()

        # Demarrer thread
        self._thread = Thread(target=self.run)
        self._thread.start()

    def fermer(self):
        self._stop_event.set()

    def run(self):
        while not self._stop_event.is_set():
            try:
                self.lire()
            except:
                self._logger.exception("DummySenseurs: Erreur lecture")
            finally:
                self._stop_event.wait(self._intervalle_lectures)


class ProducteurTransactionSenseursPassifs(GenerateurTransaction):
    """ Producteur de transactions pour les SenseursPassifs. """

    def __init__(self, contexte, noeud=socket.gethostname(), data_path='/var/opt/millegrilles/data'):
        super().__init__(contexte)
        self._noeud = noeud.replace('.', '-')
        self._data_path = data_path
        self._path_buffer: Optional[str] = None
        self._fp_buffer: Optional[int] = None
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

    def ouvrir_buffer(self):
        """
        Ouvre nouveau fichier de buffer
        :return: Liste des fichiers precedemment existants
        """
        files = [os.path.join(self._data_path, f) for f in os.listdir(self._data_path) if f.endswith('.jsonl')]

        date_formatted = datetime.datetime.utcnow().strftime(FORMAT_TIMESTAMP_FICHIER)
        self._path_buffer = os.path.join(self._data_path, 'evenements.%s.jsonl' % date_formatted)
        self._fp_buffer = os.open(self._path_buffer, os.O_CREAT | os.O_WRONLY, mode=0o755)

        return files

    def generer_transactions(self):
        # Faire une rotation du fichier de buffer
        if self._fp_buffer:
            os.close(self._fp_buffer)

        fichiers_existants = self.ouvrir_buffer()  # Ouvre un nouveau fichier de buffer

        # Traiter le fichier de buffer precedent
        self.traiter_evenements_buffer(fichiers_existants)

    def traiter_evenements_buffer(self, fichiers):
        # Grouper les transactions par appareil / heure
        # cle : uuid_senseur/appareil/heure_epoch
        # valeur : { lectures: [{ timestamp: epoch, valeur: int/float }], avg, max, min, timestamp_max, timestamp_min }
        appareils_heure_dict = dict()

        Event().wait(5)  # Attendre 5 secondes, s'assure qu'on passe a l'heure suivante si on est proche

        heure_courante = datetime.datetime.utcnow()
        heure_courante = datetime.datetime(year=heure_courante.year, month=heure_courante.month,
                                           day=heure_courante.day, hour=heure_courante.hour)
        heure_courante_ts = heure_courante.timestamp()

        conserver_fichier = list()

        for nom_fichier in fichiers:
            self._logger.debug("Traitement fichier %s", nom_fichier)
            with open(nom_fichier, 'r') as fichier:
                # evenement = fichier.readline()
                line_reader = LineReader(fichier)
                for evenement in line_reader:
                    if not evenement or not evenement.strip():
                        # Ligne vide
                        continue
                    self._logger.debug(evenement)
                    try:
                        evenement_dict = json.loads(evenement)
                    except json.decoder.JSONDecodeError:
                        self._logger.exception("Erreur decodage evenement:\n%s" % evenement)
                        continue

                    # Traiter les transactions qui ne sont pas pour l'heure en cours
                    timestamp = evenement_dict['timestamp']
                    if timestamp < heure_courante_ts:
                        timestamp_dt = datetime.datetime.fromtimestamp(timestamp)
                        timestamp_heure = datetime.datetime(year=timestamp_dt.year, month=timestamp_dt.month,
                                                            day=timestamp_dt.day, hour=timestamp_dt.hour)

                        uuid_senseur = evenement_dict['uuid_senseur']
                        senseurs = evenement_dict['senseurs']

                        for lecture in senseurs:
                            type = lecture.get('type') or ''
                            types_lectures = [t for t in lecture.keys() if t not in ['type']]

                            for tl in types_lectures:
                                cle = '/'.join([uuid_senseur, type, tl, str(int(timestamp_heure.timestamp()))])

                                lectures = appareils_heure_dict.get(cle)
                                valeur = lecture[tl]
                                if not lectures:
                                    lectures = {
                                        'timestamp': timestamp_heure,
                                        'timestamp_max': timestamp,
                                        'timestamp_min': timestamp,
                                        'lectures': list(),
                                        'avg': None,
                                        'max': valeur,
                                        'min': valeur,
                                    }
                                    appareils_heure_dict[cle] = lectures

                                lectures['timestamp_max'] = timestamp
                                lectures['lectures'].append({"timestamp": timestamp, "valeur": valeur})
                                if lectures['max'] < valeur:
                                    lectures['max'] = valeur
                                if lectures['min'] > valeur:
                                    lectures['min'] = valeur

                                appareils_heure_dict[cle] = lectures
                    else:
                        # Le fichier contient des evenements de l'heure courante, on ne le supprime pas
                        conserver_fichier.append(nom_fichier)

        # Calculer la moyenne de chaque transaction et soumettre les transactions
        for key, app in appareils_heure_dict.items():

            # Trier les lectures en ordre de timestamp
            app['lectures'] = sorted(app['lectures'], key=lambda this_lecture: this_lecture['timestamp'])

            somme_valeurs = 0.0
            nb_valeurs = 0
            for lecture in app['lectures']:
                nb_valeurs += 1
                somme_valeurs += lecture['valeur']

            moyenne = round(somme_valeurs / nb_valeurs, 2)
            app['avg'] = moyenne

            # Sauvegarder la transaction
            timestamp = app['timestamp']
            timestamp_fmt = timestamp.strftime(FORMAT_TIMESTAMP_FICHIER)

            # Remplacer instance timestamp pour int (pour sauvegarder en json)
            app['timestamp'] = int(timestamp.timestamp())

            # Transmettre les transactions
            transaction = self.soumettre_transaction(
                app,
                SenseursPassifsConstantes.EVENEMENT_DOMAINE_LECTURE,
                retourner_enveloppe=True
            )

            uuid_senseur = key.split('/')[0]
            type_senseur = key.split('/')[1]
            type_lecture = key.split('/')[2]
            nom_fichier_transaction = os.path.join(
                self._data_path,
                'transaction_%s_%s_%s_%s.json.xz' % (uuid_senseur, type_senseur, type_lecture, timestamp_fmt)
            )

            # Conserver la transaction format json compressee avec lzma (.xz)
            with lzma.open(nom_fichier_transaction, 'w') as fichier_transaction:
                json_dump = json.dumps(transaction, sort_keys=True)
                fichier_transaction.write(json_dump.encode('utf-8'))

        # Supprimer les fichiers d'evenement
        for fichier in fichiers:
            if fichier not in conserver_fichier:
                # Le fichier d'evenements peut etre supprime
                os.remove(fichier)

        self._logger.debug("Fin creation transactions")

    def transmettre_lecture_senseur(self, dict_lecture, version=6):
        # Preparer le dictionnaire a transmettre pour la lecture
        if not self._path_buffer:
            self.generer_transactions()

        message = dict_lecture.copy()

        # Verifier valeurs qui doivent etre presentes
        if message.get(SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR) is None:
            raise ValueError("L'identificateur du senseur (%s) doit etre fourni." %
                             SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR)
        if message.get(SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE) is None:
            raise ValueError("Le temps de la lecture (%s) doit etre fourni." %
                             SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE)

        # Ajouter le noeud s'il n'a pas ete fourni
        if message.get(SenseursPassifsConstantes.TRANSACTION_NOEUD) is None:
            message[SenseursPassifsConstantes.TRANSACTION_NOEUD] = self._noeud

        self._logger.debug("Message a transmettre: %s" % str(message))

        enveloppe = self.emettre_message(
            message,
            'evenement.' + SenseursPassifsConstantes.EVENEMENT_DOMAINE_LECTURE,
            retourner_enveloppe=True
        )

        # Sauvegarder l'enveloppe dans le buffer d'evenements
        evenement = json.dumps(enveloppe).encode('utf-8') + b'\n'
        os.write(self._fp_buffer, evenement)

        return enveloppe

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
        sys.exit(1)


class LineReader:

    def __init__(self, fichier):
        self._fichier = fichier

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        line = self._fichier.readline()
        if line:
            return line
        else:
            raise StopIteration()


class MessageCallback(BaseCallback):

    def __init__(self, contexte, noeud: DemarreurNoeud):
        super().__init__(contexte)
        self._noeud = noeud
        self.__channel = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        # routing_key_split = routing_key.split('.')
        # exchange = method.exchange

        if routing_key.startswith('ceduleur'):
            indicateurs = message_dict['indicateurs']
            if 'heure' in indicateurs:
                self._noeud.produire_transactions()
        else:
            self.__logger.error("Message de type inconnu : %s" % routing_key)


if __name__ == "__main__":
    demarreur = DemarreurNoeud()
    main()
