import logging

from millegrilles.util.RestaurerApplication import RestaurerApplication

class RestaurerApplicationTest:

    def __init__(self):
        self.restaurer_application = RestaurerApplication()

    def executer(self):
        self.restaurer_application.configurer_parser()
        self.restaurer_application.parse()
        self.restaurer_application.initialiser()

        self.restaurer_application.executer()


def main():
    logging.basicConfig()
    logging.getLogger('__main__').setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.INFO)
    logging.getLogger('millegrilles.util.RestaurerApplication').setLevel(logging.DEBUG)
    test = RestaurerApplicationTest()
    test.executer()


if __name__ == '__main__':
    main()
