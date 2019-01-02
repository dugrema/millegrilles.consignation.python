# Module pour lire l'etat d'un UPS APC.
# coding=utf-8


import socket
from struct import pack
import re
import time
import datetime
from dateutil.parser import parse
import os
import errno
import logging

from threading import Thread

from millegrilles.domaines.SenseursPassifs import ProducteurTransactionSenseursPassifs, SenseursPassifsConstantes


class ApcupsConstantes:

    MAP_EVENEMENTS = {
        '9': 'COMMUNICATION_PERDUE',
        '6': 'FERMETURE_APCUPSD',
        'R': 'DEMARRAGE_APCUPSD',
        '*': 'PANNE',
        '5': 'SUR_BATTERIES',
        'G': 'RETOUR_SECTEUR',
        '@': 'SUR_SECTEUR'
    }


class ApcupsdCollector:
    """ Copie de https://github.com/python-diamond/Diamond/blob/master/src/collectors/apcupsd/apcupsd.py """

    def __init__(self, no_senseur, hostname='localhost', port=3551, pipe_path='/run/mg_apcupsd_messages'):
        self._config = {
            'no_senseur': no_senseur,
            'path':     'apcupsd',
            'hostname': hostname,
            'port': port,
            'pipe_path': pipe_path,
            'metrics': ['LINEV', 'LOADPCT', 'BCHARGE', 'TIMELEFT', 'BATTV',
                        'NUMXFERS', 'TONBATT', 'MAXLINEV', 'MINLINEV',
                        'OUTPUTV', 'ITEMP', 'LINEFREQ', 'CUMONBATT', ],
        }
        self._dernier_evenement = datetime.datetime.now(tz=datetime.timezone.utc)
        self._callback_soumettre = None
        # self._producteur_transactions = ProducteurTransactionSenseursPassifs()

        self.thread_events = Thread(target=self.ecouter_evenements)
        self._lecture_evenements_actif = False

        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

    def start(self, callback_soumettre):
        """ Demarre les thread data et evenements """

        self._callback_soumettre = callback_soumettre
        self.thread_events.start()  # Demarrer thread evenements

    def fermer(self):
        self._lecture_evenements_actif = False
        with open(self._config['pipe_path'], 'w') as pipe:
            pipe.write('FERMER')

    def get_data(self):
        # Get the data via TCP stream
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self._config['hostname'], int(self._config['port'])))

        # Packet is pad byte, size byte, and command
        s.send(pack('xb6s', 6, b'status'))

        # Ditch the header
        s.recv(1024)
        time.sleep(.25)
        data = s.recv(4096)

        # We're done. Close the socket
        s.close()
        return data

    def get_evenements(self):
        # Get the data via TCP stream
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self._config['hostname'], int(self._config['port'])))

        # Packet is pad byte, size byte, and command
        s.send(pack('xb6s', 6, b'events'))

        # Ditch the header
        time.sleep(.25)
        data = s.recv(4096)

        # We're done. Close the socket
        s.close()

        self._logger.debug("Events data: %s" % data)
        split_bytes = data.split(b'\n\x00')
        self._logger.debug("Split bytes events: %s" % str(split_bytes))

        regex_metric = re.compile('(.?)([0-9-: ]{25})\s{2}(.*)')
        contenu = []
        for event in split_bytes:
            matches = re.search(regex_metric, str(event))
            if matches:
                self._logger.debug("Commande: %s, Date: %s, Event: %s" % (matches.group(1), matches.group(2), matches.group(3)))
                etat_ups = ApcupsConstantes.MAP_EVENEMENTS[matches.group(1)]
                if not etat_ups:
                    etat_ups = matches.group(1)
                date = parse(matches.group(2))
                message = matches.group(3)
                contenu.append({
                    'etat_ups': etat_ups,
                    'date': date,
                    'message': message
                })

        return contenu

    def ecouter_evenements(self):
        # Ouvrir un pipe utilise pour recevoir l'etat de APCUPSD
        pipe_fichier = self._config['pipe_path']
        self._logger.info("Demarrage thread ecoute evenements sur %s" % pipe_fichier)

        try:
            os.mkfifo(pipe_fichier)
        except OSError as oe:
            if oe.errno != errno.EEXIST:
                raise

        self._lecture_evenements_actif = True

        while self._lecture_evenements_actif:
            with open(pipe_fichier, 'r') as pipe:
                while self._lecture_evenements_actif:
                    line = pipe.read().strip()
                    self._logger.debug("Pipe event: %s" % line)
                    if line == 'FERMER':
                        self._lecture_evenements_actif = False
                    elif line in ApcupsConstantes.MAP_EVENEMENTS.values():
                        self.transmettre_evenements()
                    else:
                        self._logger.warning("Commande UPS inconne: %s" % line)

                    if len(line) == 0:
                        self._logger.debug("Reouvrir le pipe")
                        break  # Va reouvrir le pipe et bloquer

                    self._logger.debug("Contenu: %s" % str(line))

        self._logger.info("Fermeture thread lecture evenements sur pipe %s" % pipe_fichier)

    def collect(self):
        metrics = {}
        raw = {}

        data = self.get_data()

        data = data.split(b'\n\x00')
        self._logger.debug("Data : %s" % str(data))

        regex_metric = re.compile('([A-Z]*) +:(.*)')

        for d in data:
            # matches = re.search("([A-Z]+):(.*)$", d)
            matches = re.search(regex_metric, str(d))
            if matches:
                value = matches.group(2).strip()
                raw[matches.group(1)] = matches.group(2).strip()
                vmatch = re.search("([0-9.]+)", value)
                if not vmatch:
                    continue
                try:
                    value = float(vmatch.group(1))
                except ValueError:
                    continue
                metric_key = matches.group(1)
                self._logger.debug("Key: %s, Value: %s" % (metric_key, raw[metric_key]))
                metrics[matches.group(1)] = value

        # Convertir les valeurs numeriques
        contenu = dict()
        for metric in self._config['metrics']:
            if metric not in metrics:
                continue

            value = metrics[metric]
            if metric in ['TONBATT', 'CUMONBATT', 'NUMXFERS', 'LINEV', 'LOADPCT', 'BCHARGE']:
                contenu[metric] = value
            elif metric in ['TIMELEFT']:
                contenu[metric] = value * 60.0  # Convertir minutes en secondes
            elif metric in ['BATTV', 'LINEV']:
                contenu[metric] = value * 1000.0  # Convertir en mV
            else:
                contenu[metric] = raw[metric]

        self._logger.debug("Metriques: %s" % str(contenu))

        return contenu

    def transmettre_evenements(self):
        """ Transmet les evenements nouveaux depuis le demarrage du programme. """

        evenements = self.get_evenements()
        dernier_evenement = evenements[-1]
        for evenement in evenements:
            inclure_etat = (evenement == dernier_evenement)  # Inclure etat actuel pour le dernier evenement
            # Verifier si l'evenement a deja ete transmis
            if self._dernier_evenement <= evenement['date']:
                self._dernier_evenement = evenement['date']
                self._transmettre_evenement(evenement, inclure_etat=inclure_etat)

    def transmettre_etat(self):
        """ Utiliser pour lire et transmettre l'etat courant du UPS """

        self._transmettre_evenement({'date': datetime.datetime.now(tz=datetime.timezone.utc)})

    def _transmettre_evenement(self, evenement, inclure_etat=True):
        """
        Utiliser pour transmettre un evenement du UPS

        :param inclure_etat: Mettre true pour inclure l'etat courant du UPS.
        """

        contenu_message = evenement.copy()
        no_senseur = self._config['no_senseur']

        contenu_message[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR] = no_senseur

        # Convertir l'element date -> temps_lect
        contenu_message[SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE] = int(contenu_message['date'].timestamp())
        del (contenu_message['date'])

        if inclure_etat:
            # On va chercher l'etat courand du UPS
            etat = self.collect()
            self._logger.debug("Etat actuel: %s" % str(etat))
            contenu_message.update(etat)

            # Convertir certains elements en format standard
            contenu_message['millivolt'] = contenu_message['BATTV']

        # self._producteur_transactions.transmettre_lecture_senseur(contenu_message)
        self._callback_soumettre(contenu_message)
