
from millegrilles.dao.Configuration import TransactionConfiguration

class TestNoms:

    def test_nom_module(self):
        print(instance.__class__.__module__.replace(".", "_"))


instance=TransactionConfiguration()

test=TestNoms()
test.test_nom_module()