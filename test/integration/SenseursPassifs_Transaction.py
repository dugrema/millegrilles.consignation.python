from mgdomaines.appareils.SenseursPassifs import ProducteurTransactionSenseursPassifs
import datetime


class TransactionSenseursPassifsTest:

    def __init__(self):
        self._producteur = ProducteurTransactionSenseursPassifs()

    def test1(self):
        temps_lecture = datetime.datetime.now()
        # temps_lecture_ajuste = temps_lecture + datetime.timedelta(hours=4)

        message_dict = dict()
        message_dict['senseur'] = 2
        message_dict['temps_lecture'] = int(temps_lecture.timestamp())
        message_dict['temperature'] = 25.0
        message_dict['humidite'] = 67.2
        message_dict['pression'] = 103.3
        message_dict['bat_mv'] = 3498
        message_dict['hachi-parmentier'] = 'Nah nah nah, nah!'
        uuid_transaction = self._producteur.transmettre_lecture_senseur(message_dict)
        print("Sent: UUID:%s = %s" % (uuid_transaction, message_dict))


test = TransactionSenseursPassifsTest()

# TEST
print("Envoyer message")
test._producteur.connecter()

test.test1()

test._producteur.deconnecter()

# FIN TEST

