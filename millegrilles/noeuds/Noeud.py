#!/usr/bin/python3

# Module qui permet de demarrer les appareils sur un Raspberry Pi
import traceback
import argparse
import logging
import random
import threading
import sys
import datetime
import os
import json
import lzma
import signal
import time

from threading import Event, Thread
from typing import Optional

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import ExceptionConnectionFermee, BaseCallback
from millegrilles import Constantes
from millegrilles.Constantes import SenseursPassifsConstantes, ConstantesSecurityPki
from millegrilles.SecuritePKI import GestionnaireEvenementsCertificat
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.util.Daemon import Daemon

from mgdomaines.appareils.AffichagesPassifs import AffichageAvecConfiguration


FORMAT_TIMESTAMP_FICHIER = '%Y%m%d%H%M'
FORMAT_TIMESTAMP_MOIS = '%Y%m'


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
        self._apcupsd = None
        self._dummysenseurs = None

        self._contexte = ContexteRessourcesMilleGrilles()
        self._producteur_transaction: Optional[ProducteurTransactionSenseursPassifs] = None
        self.__certificat_event_handler = GestionnaireEvenementsCertificat(self._contexte)
        self.__channel = None

        self._chargement_reussi = False  # Vrai si au moins un module a ete charge
        self._stop_event = Event()
        self._stop_event.set()  # Set initiale, faire clear pour activer le processus

        self._message_handler: Optional[GestionnaireMessages] = None

        self._thread_transactions: Optional[Thread] = None  # Thread de traitement du buffer, tranmission de transactions

        self._noeud_id = os.environ['MG_NOEUD_ID']
        self.__info_noeud: Optional[dict] = None

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
            '--dummylcd', action="store_true", required=False,
            help="Initalise un affichage dummy vers logs, pour tester AffichagesPassifs"
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

    def restart(self):
        Daemon.restart(self)

    def exit_gracefully(self, signum=None, frame=None):
        self._logger.info("Fermer noeud, signal: %d" % signum)
        self.fermer()

    def on_channel_open(self, channel):
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)
        self.__channel = channel
        self.__certificat_event_handler.initialiser()

        self._message_handler = GestionnaireMessages(self._contexte, self)
        self._message_handler.initialiser()

        # self.contexte.message_dao.enregistrer_callback(queue='', callback=self._message_handler.callbackAvecAck)
        # self.contexte.message_dao.inscrire_topic(
        #     self.contexte.configuration.exchange_defaut,
        #     ['ceduleur.#'],
        #     self._message_handler.callbackAvecAck
        # )

    def on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self._logger.info("MQ Channel ferme")
        if not self._stop_event:
            self._contexte.message_dao.enter_error_state()

    def demander_informations_noeud(self):
        queue_reponse = self._message_handler.queue_reponse

        if queue_reponse is not None:
            self._logger.warning("Demander information noeud %s" % self.noeud_id)
            self.contexte.generateur_transactions.transmettre_requete(
                {'noeud_id': self.noeud_id},
                'SenseursPassifs',
                action='getNoeud',
                correlation_id='informationNoeudSenseurs',
                reply_to=self._message_handler.queue_reponse,
                ajouter_certificats=True
            )
        else:
            self._logger.info("Attente demande information noeud, Q reponse pas prete")

    def conserver_informations_noeud_senseurs(self, info_noeud: dict):
        self._logger.info("Information noeud recues : %s" % info_noeud)
        self.__info_noeud = info_noeud

    def run(self):
        self._logger.info("Demarrage Daemon")
        self.setup_modules()

        code_retour = 0

        if self._chargement_reussi:
            self._stop_event.clear()  # Permettre de bloquer sur le stop_event.
        else:
            code_retour = 2  # Erreur connexion a MQ

        while not self._stop_event.is_set():
            # Faire verifications de fonctionnement, watchdog, etc...

            try:
                if self.info_noeud is None:
                    self.demander_informations_noeud()
                else:
                    self._logger.debug("Configuration noeud : %s", self.info_noeud)
            except AttributeError:
                self._logger.debug("Connexion MQ pas prete pour requete info noeud")

            try:
                self.traiter_backlog_messages()
            except Exception:
                self._logger.exception("Erreur traitement backlog de messages")

            # Sleep
            self._stop_event.wait(self._intervalle_entretien)
        self._logger.info("Fin execution Daemon")

        self._logger.info("Main terminee, finalisation et sortie.")
        try:
            self.__finalisation()
        finally:
            sys.exit(code_retour)

    def setup_modules(self):
        # Charger la configuration et les DAOs
        if self._args.debug:
            self._logger.setLevel(logging.DEBUG)

        self._logger.info("Setup modules")
        doit_connecter = not self._args.noconnect
        self._contexte.initialiser(init_message=doit_connecter)

        if doit_connecter:
            self._contexte.message_dao.register_channel_listener(self)

            self._producteur_transaction = ProducteurTransactionSenseursPassifs(
                self._contexte, noeud=self, data_path=self._args.data)
        else:
            self._logger.info("Mode noconnect, les messages sont affiches dans le log uniquement")
            self._producteur_transaction = ProducteurTransactionNoconnect(data_path=self._args.data)

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

        if self._args.dummylcd:
            self.inclure_dummylcd()

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
        no_senseur = self.noeud_id + '/dummy1'
        self._dummysenseurs = DummySenseurs(no_senseur=no_senseur, noeud=self)
        self._dummysenseurs.start(self.transmettre_lecture_callback)
        self._chargement_reussi = True

    def inclure_dummylcd(self):
        self._logger.info("Activer Dummy LCD")
        self._dummylcd = DummyLcd(self.contexte, self.noeud_id)
        self._dummylcd.start()

    def transmettre_lecture_callback(self, dict_lecture):
        self._producteur_transaction.transmettre_lecture_senseur(dict_lecture, version=5)

    def produire_transactions(self):
        if not self._thread_transactions or not self._thread_transactions.is_alive():
            # Demarrer une thread pour produire les fichiers de transactions et les soumettre
            self._thread_transactions = Thread(
                name="transactions", target=self._producteur_transaction.generer_transactions, daemon=True)
            self._thread_transactions.start()

    def traiter_backlog_messages(self):
        pass

    def resoumettre_transactions(self):
        self._producteur_transaction.resoumettre_transactions()

    def __finalisation(self):
        time.sleep(0.2)

        if threading.active_count() > 1:
            ok_threads = ['MainThread', 'pymongo_kill_cursors_thread']
            for thread in threading.enumerate():
                if thread.name not in ok_threads:
                    self._logger.error("Thread ouverte apres demande de fermeture: %s" % thread.name)

            time.sleep(5)
            for thread in threading.enumerate():
                if thread.name not in ok_threads:
                    if not thread.isDaemon():
                        self._logger.warning("Non-daemon thread encore ouverte apres demande de fermeture: %s" % thread.name)

    @property
    def contexte(self):
        return self._contexte

    @property
    def info_noeud(self):
        return self.__info_noeud

    @property
    def noeud_id(self):
        return self._noeud_id


# Simulation de l'output d'un AM2302
class DummySenseurs:

    def __init__(self, no_senseur, noeud, intervalle_lectures=5):
        self._no_senseur = no_senseur
        self._noeud = noeud
        self._intervalle_lectures = intervalle_lectures
        self._callback_soumettre = None
        self._stop_event = Event()
        self._thread = None

        self._stop_event.set()
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def lire(self):
        humidite = random.randrange(0, 1000) / 10
        temperature = random.randrange(-500, 500) / 10

        timestamp = int(datetime.datetime.now().timestamp())
        dict_message = {
            'uuid_senseur': self._no_senseur,
            'senseurs': {
                'dummy/temperature': {
                    'valeur': round(temperature, 1),
                    'timestamp': timestamp,
                    'type': 'temperature',
                },
                'dummy/humidite': {
                    'valeur': round(humidite, 1),
                    'timestamp': timestamp,
                    'type': 'humidite',
                }
            }
        }

        self._callback_soumettre(dict_message)

    def start(self, callback_soumettre):
        self._callback_soumettre = callback_soumettre
        self._stop_event.clear()

        # Demarrer thread
        self._thread = Thread(name="DummySenseurs", target=self.run, daemon=True)
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


class DummyLcd(AffichageAvecConfiguration):

    def __init__(self, contexte, noeud_id: str = None, timezone_horloge: str = None, intervalle_secs=30):
        super().__init__(contexte, noeud_id, timezone_horloge, intervalle_secs)

    def maj_affichage(self, lignes_affichage):
        super().maj_affichage(lignes_affichage)
        print(self._lignes_ecran)


class ProducteurTransactionSenseursPassifs(GenerateurTransaction):
    """ Producteur de transactions pour les SenseursPassifs. """

    def __init__(self, contexte, noeud, data_path='/var/opt/millegrilles/data'):
        super().__init__(contexte)
        self.noeud = noeud
        self._data_path = data_path
        self._path_buffer: Optional[str] = None
        self._fp_buffer: Optional[int] = None
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

    def ouvrir_buffer(self):
        """
        Ouvre nouveau fichier de buffer
        :return: Liste des fichiers precedemment existants
        """
        try:
            os.mkdir(self._data_path)
        except FileExistsError:
            pass

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
                    try:
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
                        uuid_senseur = evenement_dict['uuid_senseur']
                        noeud_id = evenement_dict['noeud_id']
                        senseurs = evenement_dict['senseurs']

                        for type, lecture in senseurs.items():
                            timestamp = lecture['timestamp']
                            if timestamp < heure_courante_ts:
                                timestamp_dt = datetime.datetime.fromtimestamp(timestamp)
                                timestamp_heure = datetime.datetime(year=timestamp_dt.year, month=timestamp_dt.month,
                                                                    day=timestamp_dt.day, hour=timestamp_dt.hour)

                                cle = '/'.join([uuid_senseur, type, str(int(timestamp_heure.timestamp()))])

                                lectures = appareils_heure_dict.get(cle)
                                valeur = lecture['valeur']
                                if not lectures:
                                    lectures = {
                                        'timestamp': timestamp_heure,
                                        'timestamp_max': timestamp,
                                        'timestamp_min': timestamp,
                                        'lectures': list(),
                                        'avg': None,
                                        'max': valeur,
                                        'min': valeur,
                                        'senseur': type,
                                        'type': lecture['type'],
                                        'uuid_senseur': uuid_senseur,
                                        'noeud_id': noeud_id,
                                    }
                                    appareils_heure_dict[cle] = lectures

                                lectures['timestamp_max'] = timestamp
                                lectures['lectures'].append({"timestamp": timestamp, "valeur": valeur})
                                if valeur is not None:
                                    if lectures['max'] < valeur:
                                        lectures['max'] = valeur
                                    if lectures['min'] > valeur:
                                        lectures['min'] = valeur

                                appareils_heure_dict[cle] = lectures
                            else:
                                # Le fichier contient des evenements de l'heure courante, on ne le supprime pas
                                conserver_fichier.append(nom_fichier)
                    except Exception:
                        self._logger.exception("Erreur traitement ligne %s" % evenement)

        # Calculer la moyenne de chaque transaction et soumettre les transactions
        for key, app in appareils_heure_dict.items():

            # Trier les lectures en ordre de timestamp
            app['lectures'] = sorted(app['lectures'], key=lambda this_lecture: this_lecture['timestamp'])

            somme_valeurs = 0.0
            nb_valeurs = 0
            for lecture in app['lectures']:
                val_lecture = lecture.get('valeur')
                if val_lecture is not None:
                    nb_valeurs += 1
                    somme_valeurs += val_lecture

            try:
                moyenne = round(somme_valeurs / nb_valeurs, 2)
                app['avg'] = moyenne
            except ZeroDivisionError:
                app['avg'] = None

            # Sauvegarder la transaction
            timestamp = app['timestamp']
            timestamp_fmt = timestamp.strftime(FORMAT_TIMESTAMP_FICHIER)
            timestamp_mois = timestamp.strftime(FORMAT_TIMESTAMP_MOIS)

            # Remplacer instance timestamp pour int (pour sauvegarder en json)
            app['timestamp'] = int(timestamp.timestamp())

            try:
                partition = self.noeud.info_noeud['partition']
            except (TypeError, KeyError):
                partition = None

            # Transmettre les transactions
            transaction = self.soumettre_transaction(
                app,
                domaine_action=SenseursPassifsConstantes.DOMAINE_NOM,
                action=SenseursPassifsConstantes.EVENEMENT_DOMAINE_LECTURE,
                partition=partition,
                retourner_enveloppe=True
            )

            uuid_senseur = key.split('/')[0]
            type_senseur = key.split('/')[1]
            type_lecture = key.split('/')[2]
            try:
                os.mkdir(os.path.join(self._data_path, timestamp_mois), 0o755)
            except FileExistsError:
                pass  # Ok

            nom_fichier_transaction = os.path.join(
                self._data_path,
                timestamp_mois,
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

    def resoumettre_transactions(self):
        self._logger.info("Resoumettre les transactions du repertoire data")

        try:
            partition = self.noeud.info_noeud['partition']
        except:
            self._logger.error("Erreur resoumission transactions, partitions pas chargee")
            raise Exception("Erreur resoumission transactions, partitions pas chargee")

        mois_archives = os.listdir(self._data_path)
        for mois in mois_archives:
            fullpath_mois = os.path.join(self._data_path, mois)
            if os.path.isdir(fullpath_mois):
                self._logger.info("Soumettre transactions sous : %s" % fullpath_mois)
                fichiers_mois = os.listdir(fullpath_mois)
                for nom_archive in fichiers_mois:
                    if nom_archive.endswith('.json.xz'):
                        fullpath_archive = os.path.join(fullpath_mois, nom_archive)
                        self.soumettre_archive(fullpath_archive, partition)

    def soumettre_archive(self, path_archive: str, partition: str):
        print("Resoumettre archive transactions %s" % path_archive)
        with lzma.open(path_archive, 'r') as fichier:
            for line in fichier:
                transaction = json.loads(line)
                routing = 'transaction.SenseursPassifs.%s.lecture' % partition
                self.emettre_message(transaction, routing)

    def transmettre_lecture_senseur(self, dict_lecture, version=6):
        # Preparer le dictionnaire a transmettre pour la lecture
        if not self._path_buffer:
            self.generer_transactions()

        message = dict_lecture.copy()

        # Verifier valeurs qui doivent etre presentes
        if message.get(SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR) is None:
            raise ValueError("L'identificateur du senseur (%s) doit etre fourni." %
                             SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR)

        # Ajouter le noeud s'il n'a pas ete fourni
        if message.get('noeud_id') is None:
            message['noeud_id'] = self.noeud.noeud_id

        self._logger.debug("Message a transmettre: %s" % str(message))

        info_noeud = self.noeud.info_noeud
        try:
            partition = info_noeud['partition']
            routing_key = 'evenement.SenseursPassifs.%s.%s' % (partition, SenseursPassifsConstantes.EVENEMENT_DOMAINE_LECTURE)
        except (TypeError, KeyError):
            partition = None
            routing_key = 'evenement.SenseursPassifs.%s' % SenseursPassifsConstantes.EVENEMENT_DOMAINE_LECTURE

        enveloppe = self.emettre_message(
            message, routing_key,
            domaine=SenseursPassifsConstantes.DOMAINE_NOM,
            action=SenseursPassifsConstantes.TRANSACTION_LECTURE,
            partition=partition,
            retourner_enveloppe=True
        )

        # Sauvegarder l'enveloppe dans le buffer d'evenements
        evenement = json.dumps(enveloppe).encode('utf-8') + b'\n'
        os.write(self._fp_buffer, evenement)

        return enveloppe


class ProducteurTransactionNoconnect(GenerateurTransaction):
    
    def __init__(self, data_path: str = None):
        self.data_path = data_path
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
    
    def transmettre_lecture_senseur(self, dict_lecture, version=6):
        # Preparer le dictionnaire a transmettre pour la lecture
        message = dict_lecture.copy()
        self.__logger.warning("Lecture \n" + json.dumps(message, indent=2))


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


class GestionnaireMessages(BaseCallback):

    def __init__(self, contexte, noeud: DemarreurNoeud):
        super().__init__(contexte)
        self.__noeud = noeud
        self.__channel = None
        self.__queue_reponse = None
        self.__routing_cert = None
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def initialiser(self):
        self.__logger.debug("Initialisation GestionnaireMessages")

        if self.contexte.message_dao is not None:
            self.contexte.message_dao.register_channel_listener(self)

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        self.__channel = channel
        self.__channel.queue_declare(queue='', exclusive=True, callback=self.register_mq_handler)

    def register_mq_handler(self, queue):
        nom_queue = queue.method.queue
        self.__queue_reponse = nom_queue
        self.__logger.info("Q reponse : %s", self.__queue_reponse)

        self.__logger.debug("Transmission certificat PKI a l'initialisation")
        signateur_transactions = self.contexte.signateur_transactions
        signateur_transactions.emettre_certificat()

        enveloppe = signateur_transactions.enveloppe_certificat_courant
        fingerprint = enveloppe.fingerprint
        routing_key = '%s.%s' % (ConstantesSecurityPki.EVENEMENT_REQUETE, fingerprint)

        exchange_defaut = self.configuration.exchange_defaut
        self.__channel.queue_bind(queue=nom_queue, exchange=exchange_defaut, routing_key=routing_key, callback=None)
        self.__channel.basic_consume(self.callbackAvecAck, queue=nom_queue, auto_ack=False)
        self.__routing_cert = routing_key

        routing_key_cedule = 'evenement.global.cedule'
        self.__channel.queue_bind(queue=nom_queue, exchange=exchange_defaut, routing_key=routing_key_cedule, callback=None)
        self.__channel.basic_consume(self.callbackAvecAck, queue=nom_queue, auto_ack=False)

        routing_key_commandes = 'commande.senseurpassif.%s.*' % self.__noeud.noeud_id
        self.__channel.queue_bind(queue=nom_queue, exchange=exchange_defaut, routing_key=routing_key_commandes, callback=None)
        self.__channel.basic_consume(self.callbackAvecAck, queue=nom_queue, auto_ack=False)

        # Premiere demande d'information
        self.__noeud.demander_informations_noeud()

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def traiter_message(self, ch, method, properties, body):
        # Implementer la lecture de messages, specialement pour transmettre un certificat manquant
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        validateur = self.contexte.validateur_message
        validateur.verifier(message_dict)

        routing_key = method.routing_key
        action = routing_key.split('.')[-1]
        correlation_id = properties.correlation_id

        if routing_key == self.__routing_cert:
            # Emettre notre certificat pour s'assurer qu'il soit sauvegarde
            chaine_certs = self.contexte.signateur_transactions.chaine_certs
            enveloppe = self.contexte.signateur_transactions.enveloppe_certificat_courant
            fingerprint = enveloppe.fingerprint
            message_cert = {'chaine_pem': chaine_certs, 'fingerprint': fingerprint}
            self.contexte.generateur_transactions.emettre_certificat(chaine_certs)
            # Repondre au demandeur
            reply_to = properties.reply_to
            self.contexte.generateur_transactions.transmettre_reponse(
                message_cert, reply_to, correlation_id, ajouter_certificats=True)
        elif action == 'cedule':
            flag_heure = message_dict.get('flag_heure')
            if flag_heure:
                self.__noeud.produire_transactions()
        elif correlation_id == 'informationNoeudSenseurs':
            self.__noeud.conserver_informations_noeud_senseurs(message_dict)
        elif action == 'transmettreTransactions':
            self.__noeud.resoumettre_transactions()
        else:
            raise Exception("Routing non gere: %s" % routing_key)

    @property
    def queue_reponse(self):
        return self.__queue_reponse


if __name__ == "__main__":
    demarreur = DemarreurNoeud()
    signal.signal(signal.SIGINT, demarreur.exit_gracefully)
    signal.signal(signal.SIGTERM, demarreur.exit_gracefully)
    main()
