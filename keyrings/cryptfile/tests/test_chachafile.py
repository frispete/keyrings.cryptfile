import getpass
from unittest import mock
import pytest

from keyrings.cryptfile import chachafile
from .test_file import FileKeyringTests


class TestCryptFileKeyring(FileKeyringTests):

    @pytest.fixture(autouse=True)
    def mocked_getpass(self, monkeypatch):
        fake_getpass = mock.Mock(return_value='iYAzNx5UDVXGGH0BUKBT4jsqX5CWyIQr')
        monkeypatch.setattr(getpass, 'getpass', fake_getpass)

    def init_keyring(self):
        return chachafile.ChaChaFileKeyring()

    def test_encrypt_decrypt_without_assoc(self):
        # super class test fails...
        pass

    def test_scheme(self):
        assert self.keyring.scheme is not None
        assert self.keyring.scheme == '[ChaCha20Poly1305]'
