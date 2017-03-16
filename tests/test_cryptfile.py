import unittest
from unittest import mock

from .test_file import FileKeyringTests

from keyrings.cryptfile import cryptfile

def is_crypto_supported():
    try:
        __import__('argon2.low_level')
        __import__('Crypto.Cipher.AES')
    except ImportError:
        return False
    return True


@unittest.skipUnless(is_crypto_supported(),
                     "Need argon2_cffi and PyCryptodome package")
class CryptFileKeyringTests(FileKeyringTests):

    def setUp(self):
        super(CryptFileKeyringTests, self).setUp()
        fake_getpass = mock.Mock(return_value='abcdef')
        self.patcher = mock.patch('getpass.getpass', fake_getpass)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def init_keyring(self):
        kr = cryptfile.CryptFileKeyring()
        mode = self.__class__.__name__[:3]
        if mode in kr._get_mode():
            kr.aesmode = mode
        return kr

    def test_file(self):
        self.assertTrue(self.keyring._check_file() != True)


@unittest.skipUnless(is_crypto_supported(),
                     "Need argon2_cffi and PyCryptodome package")
class CryptFileKeyringTestCase(CryptFileKeyringTests, unittest.TestCase):
    """ test default AES mode (GCM) """

#@unittest.skipUnless(is_crypto_supported(),
#                     "Need argon2_cffi and PyCryptodome package")
#class EAXCryptFileKeyringTestCase(CryptFileKeyringTests, unittest.TestCase):
#    """ test EAX mode """

#@unittest.skipUnless(is_crypto_supported(),
#                     "Need argon2_cffi and PyCryptodome package")
#class CCMCryptFileKeyringTestCase(CryptFileKeyringTests, unittest.TestCase):
#    """ test CCM mode """

#@unittest.skipUnless(is_crypto_supported(),
#                     "Need argon2_cffi and PyCryptodome package")
#class OCCBCryptFileKeyringTestCase(CryptFileKeyringTests, unittest.TestCase):
#    """ test OCB mode """
