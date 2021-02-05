import os
import tempfile
import sys
import errno
import getpass
import configparser

import pytest
from unittest import mock

from keyring.testing.backend import BackendBasicTests
from keyring.testing.util import random_string

from keyrings.cryptfile import file
from keyrings.cryptfile.file_base import encodebytes
from keyrings.cryptfile.escape import escape as escape_for_ini

from keyring.errors import PasswordDeleteError


class FileKeyringTests(BackendBasicTests):
    @pytest.fixture(autouse=True)
    def _init_properties_for_file(self):
        self.keyring.file_path = tempfile.mktemp()
        yield

    @pytest.fixture(autouse=True)
    def _cleanup_for_file(self):
        yield
        try:
            os.remove(self.keyring.file_path)  # remove file
        except OSError:  # is a directory
            e = sys.exc_info()[1]
            if e.errno != errno.ENOENT:  # No such file or directory
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

        assert password == self.keyring.decrypt(encrypted)

    def test_encrypt_decrypt_without_assoc(self):
        # generate keyring
        self.set_password('system', 'user', 'password')
        config = self.get_config()
        # generate and save password without assoc data
        encrypted = self.keyring.encrypt('password'.encode('utf-8'))
        password_base64 = '\n' + encodebytes(encrypted).decode()
        config.set('system', 'user', password_base64)
        self.save_config(config)
        assert self.keyring.get_password('system', 'user') == 'password'

    def test_delete_password(self):
        self.set_password('system', 'user', 'password')
        with pytest.raises(PasswordDeleteError):
            self.keyring.delete_password('system', 'xxxx')
        with pytest.raises(PasswordDeleteError):
            self.keyring.delete_password('xxxxxx', 'xxxx')

    def test_file(self):
        if not hasattr(self.keyring, '_check_file'):
            return
        # keyring file doesn't exist yet
        assert self.keyring._check_file() is False
        # generate keyring
        self.set_password('system', 'user', 'password')
        # valid keyring file exist now
        assert self.keyring._check_file() is True
        # lock keyring
        self.keyring._lock()
        # fetch password from keyring
        assert self.keyring.get_password('system', 'user') == 'password'
        # test missing password reference
        config = self.get_config()
        krsetting = escape_for_ini('keyring-setting')
        pwref = escape_for_ini('password reference')
        # pwrefval = config.get(krsetting, pwref)
        config.remove_option(krsetting, pwref)
        self.save_config(config)
        assert self.keyring._check_file() is False

    def test_scheme(self):
        # scheme exists
        assert self.keyring.scheme is not None
        if not hasattr(self.keyring, '_check_file'):
            return

        # keyring file doesn't exist yet
        assert self.keyring._check_file() is False
        # generate keyring
        self.set_password('system', 'user', 'password')
        config = self.get_config()
        krsetting = escape_for_ini('keyring-setting')
        scheme = escape_for_ini('scheme')
        defscheme = '[PBKDF2] AES256.CFB'

        # default scheme match
        assert config.get(krsetting, scheme) == defscheme

        # invalid AES mode
        config.set(krsetting, scheme, defscheme.replace('CFB', 'XXX'))
        with pytest.raises(ValueError):
            self.keyring._check_scheme(config)

        # compatibility with former scheme format
        config.set(krsetting, scheme, 'PyCrypto ' + defscheme)
        assert self.keyring._check_scheme(config) is None

        # test with invalid KDF
        config.set(krsetting, scheme, defscheme.replace('PBKDF2', 'scrypt'))
        with pytest.raises(ValueError):
            self.keyring._check_scheme(config)

        # a missing scheme is valid
        config.remove_option(krsetting, scheme)
        self.save_config(config)
        assert self.keyring._check_file() is True

        with pytest.raises(AttributeError):
            self.keyring._check_scheme(config)

    def test_version(self):
        # version exists
        assert self.keyring.version is not None
        if not hasattr(self.keyring, '_check_version'):
            return

        # generate keyring
        self.set_password('system', 'user', 'password')
        config = self.get_config()

        # default version valid
        assert self.keyring._check_version(config) is True

        krsetting = escape_for_ini('keyring-setting')
        version = escape_for_ini('version')

        # invalid, if version is missing
        config.remove_option(krsetting, version)
        self.save_config(config)
        assert self.keyring._check_version(config) is False


class TestEncryptedFileKeyring(FileKeyringTests):
    @pytest.fixture(autouse=True)
    def crypt_fixture(self, monkeypatch):
        pytest.importorskip('Crypto')
        fake_getpass = mock.Mock(return_value='abcdef')
        monkeypatch.setattr(getpass, 'getpass', fake_getpass)

    def init_keyring(self):
        return file.EncryptedKeyring()

    def test_wrong_password(self):
        self.set_password('system', 'user', 'password')
        # we need to invalidate the keyring password here
        # in order trigger the mocked getpass.getpass()
        self.keyring._lock()
        # fake a wrong password
        getpass.getpass.return_value = 'wrong'
        with pytest.raises(ValueError):
            self.keyring._unlock()

    @pytest.mark.skipif(
        sys.platform == 'win32',
        reason="Group/World permissions aren't meaningful on Windows",
    )
    def test_keyring_not_created_world_writable(self):
        """
        Ensure that when keyring creates the file that it's not overly-
        permissive.
        """
        self.set_password('system', 'user', 'password')

        assert os.path.exists(self.keyring.file_path)
        group_other_perms = os.stat(self.keyring.file_path).st_mode & 0o077
        assert group_other_perms == 0


class TestUncryptedFileKeyring(FileKeyringTests):
    def init_keyring(self):
        return file.PlaintextKeyring()

    @pytest.mark.skipif(
        sys.platform == 'win32',
        reason="Group/World permissions aren't meaningful on Windows",
    )
    def test_keyring_not_created_world_writable(self):
        """
        Ensure that when keyring creates the file that it's not overly-
        permissive.
        """
        self.set_password('system', 'user', 'password')

        assert os.path.exists(self.keyring.file_path)
        group_other_perms = os.stat(self.keyring.file_path).st_mode & 0o077
        assert group_other_perms == 0
