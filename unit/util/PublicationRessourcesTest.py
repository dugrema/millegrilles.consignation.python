import json

from unit.helpers.TestBaseContexte import TestCaseContexte


class RequestsReponse:

    def __init__(self):
        self.status_code = 200
        self.json = {
            'ok': True,
        }
        self.headers = list()

    @property
    def text(self):
        return json.dumps(self.json)


class PublicationRessourcesTest(TestCaseContexte):

    def setUp(self) -> None:
        super().setUp()
        # self.backup_util = BackupUtil(self.contexte)
