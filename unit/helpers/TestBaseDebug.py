import logging

from unit.helpers.TestBaseContexte import TestCaseContexte


class VerifTest(TestCaseContexte):

    def testTest1(self):
        self.__class__.logger.debug("Test 1")
        self.assertTrue(True)

    def testTest2(self):
        self.__class__.logger.debug("Test 2")
        self.assertFalse(True)
