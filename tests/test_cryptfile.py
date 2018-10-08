import pytest
import unittest
from unittest import mock

from .test_file import FileKeyringTests

from keyrings.cryptfile import cryptfile
from keyrings.cryptfile._escape import escape as escape_for_ini

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

    def test_scheme(self):
        self.assertTrue(self.keyring.scheme is not None)

        # generate keyring
        self.keyring.set_password('system', 'user', 'password')
        config = self.get_config()
        krsetting = escape_for_ini('keyring-setting')
        scheme = escape_for_ini('scheme')
        defscheme = '[Argon2] AES128.GCM'

        # default scheme match
        if self.keyring.aesmode == 'GCM':
            self.assertTrue(config.get(krsetting, scheme) == defscheme)

        # invalid AES mode
        config.set(krsetting, scheme, defscheme.replace('GCM', 'XXX'))
        with pytest.raises(ValueError):
            self.keyring._check_scheme(config)

        # compatibility with former scheme format
        config.set(krsetting, scheme, 'PyCryptodome ' + defscheme)
        self.assertTrue(self.keyring._check_scheme(config) == None)

        # test with invalid KDF
        config.set(krsetting, scheme, defscheme.replace('Argon2', 'PBKDF2'))
        with pytest.raises(ValueError):
            self.keyring._check_scheme(config)

        # a missing scheme is valid
        config.remove_option(krsetting, scheme)
        self.save_config(config)
        self.assertTrue(self.keyring._check_file() == True)

        with pytest.raises(AttributeError):
            self.keyring._check_scheme(config)


@unittest.skipUnless(is_crypto_supported(),
                     "Need argon2_cffi and PyCryptodome package")
class CryptFileKeyringTestCase(CryptFileKeyringTests, unittest.TestCase):
    """ test default AES mode (GCM) """

@unittest.skipUnless(is_crypto_supported(),
                     "Need argon2_cffi and PyCryptodome package")
class EAXCryptFileKeyringTestCase(CryptFileKeyringTests, unittest.TestCase):
    """ test EAX mode """

@unittest.skipUnless(is_crypto_supported(),
                     "Need argon2_cffi and PyCryptodome package")
class CCMCryptFileKeyringTestCase(CryptFileKeyringTests, unittest.TestCase):
    """ test CCM mode """

@unittest.skipUnless(is_crypto_supported(),
                     "Need argon2_cffi and PyCryptodome package")
class OCBCryptFileKeyringTestCase(CryptFileKeyringTests, unittest.TestCase):
    """ test OCB mode """
