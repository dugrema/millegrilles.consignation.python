#!/usr/bin/python3
# Executer ce script pour demarrer le service monitor
import logging
import sys

from millegrilles.util.ServiceMonitor import ServiceMonitor, SERVICEMONITOR_LOGGING_FORMAT

logging.basicConfig(stream=sys.stdout, format=SERVICEMONITOR_LOGGING_FORMAT)
logging.getLogger(ServiceMonitor.__name__).setLevel(logging.INFO)
if __name__ == '__main__':

    ServiceMonitor().run()
