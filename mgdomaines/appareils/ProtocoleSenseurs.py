import struct
import time
import logging


# **** Protocole Senseurs Passifs ****
# Packet data format V6 (pour V5 et moins, le senseur est le premier byte)
# [0]: Version integer / senseur pour version <=5
# [1]: Senseur
# [2-3]: Short temperature
# [4-5]: Unsigned int humidite * 10
# [6-7]: Unsigned int pression
# [8-9]: Unsigned int millivolts # Starting V6
class ProtocoleSenseursPassifsNRF24l:

    def __init__(self):
        pass

    # Conversion d'un paquet. Identifie la version et remplit le dictionnaire.
    @staticmethod
    def convertir(bytes_recus):

        # Determiner la version du contenu
        contenu = dict()
        contenu["version"] = bytes_recus[0]
        contenu["senseur"] = 0

        if contenu["version"] <= 5:
            contenu["senseur"] = contenu["version"]
            contenu["version"] = 1
            ProtocoleSenseursPassifsNRF24l.convertir_5moins(bytes_recus, contenu)
        else:
            contenu["senseur"] = bytes_recus[1]
            ProtocoleSenseursPassifsNRF24l.convertir_v6(bytes_recus, contenu)

        contenu["temps_lecture"] = int(time.time())

        # Filtre de derniere minute pour empecher mauvaises lectures
        if -50.0 <= contenu.get("temperature") <= 50.0 and 0.0 <= contenu.get("humidite") <= 100.0:
            return contenu
        else:
            # Rejeter le message
            return None

    # Extraction des informations d'un paquet version 5 et moins
    @staticmethod
    def convertir_5moins(bytes_recus, contenu):

        reste_str = bytes_recus[1:7]
        logging.debug("Reste string V5- %d" % len(reste_str))
        reste_tuple = struct.unpack('hHH', reste_str)

        contenu["temperature"] = reste_tuple[0] / 10.0
        contenu["humidite"] = reste_tuple[1] / 10.0
        contenu["pression"] = reste_tuple[2] / 100.0

    # Extraction des informations d'un paquet version 6
    @staticmethod
    def convertir_v6(bytes_recus, contenu):

        reste_str = bytes_recus[2:10]
        logging.debug("Reste string V6- %d" % len(reste_str))
        reste_tuple = struct.unpack('hHHh', reste_str)

        contenu["temperature"] = reste_tuple[0] / 10.0
        contenu["humidite"] = reste_tuple[1] / 10.0
        contenu["pression"] = reste_tuple[2] / 100.0
        contenu["millivolt"] = reste_tuple[3]
