import os
import tempfile
import sys
import errno
import unittest

import pytest
from unittest import mock

from keyring.tests.test_backend import BackendBasicTests
from keyring.tests.util import random_string

from keyring.py27compat import configparser

from keyrings.cryptfile import file
from keyrings.cryptfile.file_base import encodebytes
from keyrings.cryptfile._escape import escape as escape_for_ini

from keyring.errors import PasswordDeleteError


class FileKeyringTests(BackendBasicTests):

    def setUp(self):
        super(FileKeyringTests, self).setUp()
        self.keyring.file_path = self.tmp_keyring_file = tempfile.mktemp()

    def tearDown(self):
        try:
            os.unlink(self.tmp_keyring_file)
        except (OSError,):
            e = sys.exc_info()[1]
            if e.errno != errno.ENOENT: # No such file or directory
                raise

    def get_config(self):
        # setting a password triggers keyring file creation
        config = configparser.RawConfigParser()
        config.read(self.keyring.file_path)
        return config

    def save_config(self, config):
        with open(self.keyring.file_path, 'w') as config_file:
            config.write(config_file)

    def test_encrypt_decrypt(self):
        password = random_string(20)
        # keyring.encrypt expects bytes
        password = password.encode('utf-8')
        encrypted = self.keyring.encrypt(password)

        self.assertEqual(password, self.keyring.decrypt(encrypted))

    def test_encrypt_decrypt_without_assoc(self):
        # generate keyring
        self.keyring.set_password('system', 'user', 'password')
        config = self.get_config()
        # generate and save password without assoc data
        encrypted = self.keyring.encrypt('password'.encode('utf-8'))
        password_base64 = '\n' + encodebytes(encrypted).decode()
        config.set('system', 'user', password_base64)
        self.save_config(config)
        self.assertEqual(self.keyring.get_password('system', 'user'), 'password')

    def test_delete_password(self):
        self.keyring.set_password('system', 'user', 'password')
        with pytest.raises(PasswordDeleteError):
            self.keyring.delete_password('system', 'xxxx')
        with pytest.raises(PasswordDeleteError):
            self.keyring.delete_password('xxxxxx', 'xxxx')

    def test_file(self):
        if not hasattr(self.keyring, '_check_file'):
            return
        # keyring file doesn't exist yet
        self.assertTrue(self.keyring._check_file() == False)
        # generate keyring
        self.keyring.set_password('system', 'user', 'password')
        # valid keyring file exist now
        self.assertTrue(self.keyring._check_file() == True)
        # lock keyring
        self.keyring._lock()
        # fetch password from keyring
        self.assertTrue(self.keyring.get_password('system', 'user') == 'password')
        # test missing password reference
        config = self.get_config()
        krsetting = escape_for_ini('keyring-setting')
        pwref = escape_for_ini('password reference')
        #pwrefval = config.get(krsetting, pwref)
        config.remove_option(krsetting, pwref)
        self.save_config(config)
        self.assertTrue(self.keyring._check_file() == False)

    def test_scheme(self):
        # scheme exists
        self.assertTrue(self.keyring.scheme is not None)
        if not hasattr(self.keyring, '_check_file'):
            return

        # keyring file doesn't exist yet
        self.assertTrue(self.keyring._check_file() == False)
        # generate keyring
        self.keyring.set_password('system', 'user', 'password')
        config = self.get_config()
        krsetting = escape_for_ini('keyring-setting')
        scheme = escape_for_ini('scheme')
        defscheme = '[PBKDF2] AES256.CFB'

        # default scheme match
        self.assertTrue(config.get(krsetting, scheme) == defscheme)

        # invalid AES mode
        config.set(krsetting, scheme, defscheme.replace('CFB', 'XXX'))
        with pytest.raises(ValueError):
            self.keyring._check_scheme(config)

         # compatibility with former scheme format
        config.set(krsetting, scheme, 'PyCrypto ' + defscheme)
        self.assertTrue(self.keyring._check_scheme(config) == None)

        # test with invalid KDF
        config.set(krsetting, scheme, defscheme.replace('PBKDF2', 'scrypt'))
        with pytest.raises(ValueError):
            self.keyring._check_scheme(config)

        # a missing scheme is valid
        config.remove_option(krsetting, scheme)
        self.save_config(config)
        self.assertTrue(self.keyring._check_file() == True)

        with pytest.raises(AttributeError):
            self.keyring._check_scheme(config)

    def test_version(self):
        # version exists
        self.assertTrue(self.keyring.version is not None)
        if not hasattr(self.keyring, '_check_version'):
            return

        # generate keyring
        self.keyring.set_password('system', 'user', 'password')
        config = self.get_config()

        # default version valid
        self.assertTrue(self.keyring._check_version(config) == True)

        krsetting = escape_for_ini('keyring-setting')
        version = escape_for_ini('version')

        # invalid, if version is missing
        config.remove_option(krsetting, version)
        self.save_config(config)
        self.assertTrue(self.keyring._check_version(config) == False)


class EncryptedFileKeyringTestCase(FileKeyringTests, unittest.TestCase):

    def setUp(self):
        super(EncryptedFileKeyringTestCase, self).setUp()
        self.mock_getpass()

    def mock_getpass(self, password = 'abcdef'):
        fake_getpass = mock.Mock(return_value=password)
        self.patcher = mock.patch('getpass.getpass', fake_getpass)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def init_keyring(self):
        return file.EncryptedKeyring()

    def test_wrong_password(self):
        self.keyring.set_password('system', 'user', 'password')
        self.patcher.stop()
        self.mock_getpass('wrong')
        with pytest.raises(ValueError):
            self.keyring._unlock()
        self.patcher.stop()
        self.mock_getpass()

    @unittest.skipIf(sys.platform == 'win32',
        "Group/World permissions aren't meaningful on Windows")
    def test_keyring_not_created_world_writable(self):
        """
        Ensure that when keyring creates the file that it's not overly-
        permissive.
        """
        self.keyring.set_password('system', 'user', 'password')

        self.assertTrue(os.path.exists(self.keyring.file_path))
        group_other_perms = os.stat(self.keyring.file_path).st_mode & 0o077
        self.assertEqual(group_other_perms, 0)


class UncryptedFileKeyringTestCase(FileKeyringTests, unittest.TestCase):

    def init_keyring(self):
        return file.PlaintextKeyring()

    @unittest.skipIf(sys.platform == 'win32',
        "Group/World permissions aren't meaningful on Windows")
    def test_keyring_not_created_world_writable(self):
        """
        Ensure that when keyring creates the file that it's not overly-
        permissive.
        """
        self.keyring.set_password('system', 'user', 'password')

        self.assertTrue(os.path.exists(self.keyring.file_path))
        group_other_perms = os.stat(self.keyring.file_path).st_mode & 0o077
        self.assertEqual(group_other_perms, 0)
