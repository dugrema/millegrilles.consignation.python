# Script pour demarrer un web poll

import logging

from millegrilles.util.UtilScriptLigneCommande import ModeleAvecMessageDAO
from mgdomaines.web.WebPoll import RSSFeedDownload

logger = logging.getLogger(__name__)


# Classe qui herite de ModeleAvecMessageDAO pour transmettre une transaction.
class WebPageDownloadCommandLine(ModeleAvecMessageDAO):

    def __init__(self):
        super().__init__()

    def configurer_parser(self):
        super().configurer_parser()

        self.parser.add_argument(
            'url', type=str, help="URL a telecharger"
        )

        self.parser.add_argument(
            '--domaine',
            type=str,
            required=False,
            default=RSSFeedDownload.TRANSACTION_VALEUR_DOMAINE,
            help="Domaine de la transaction"
        )

        self.parser.add_argument(
            '--debug', action="store_true", required=False,
            help="Active le debugging (logger)"
        )

    def executer(self):
        downloader = RSSFeedDownload(self.configuration, self.message_dao)
        url = self.args.url
        domaine = self.args.domaine
        downloader.produire_transaction(url, domaine)


# **** MAIN ****
if __name__ == "__main__":
    web_downloader = WebPageDownloadCommandLine()
    web_downloader.main()
