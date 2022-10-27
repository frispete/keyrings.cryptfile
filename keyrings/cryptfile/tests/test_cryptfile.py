import getpass
import pathlib
import shutil
from unittest import mock

import pytest

from .test_file import FileKeyringTests

from keyrings.cryptfile import cryptfile
from keyrings.cryptfile.escape import escape as escape_for_ini


def is_crypto_supported():
    try:
        __import__('argon2.low_level')
        __import__('Crypto.Cipher.AES')
    except ImportError:
        return False
    return True


@pytest.mark.skipif(not is_crypto_supported(),
                    reason = "Need argon2_cffi and PyCryptodome package")
class TestCryptFileKeyring(FileKeyringTests):
    @pytest.fixture(autouse=True)
    def mocked_getpass(self, monkeypatch):
        fake_getpass = mock.Mock(return_value='abcdef')
        monkeypatch.setattr(getpass, 'getpass', fake_getpass)

    def init_keyring(self):
        kr = cryptfile.CryptFileKeyring()
        mode = self.__class__.__name__[:3]
        if mode in kr._get_mode():
            kr.aesmode = mode
        return kr

    def test_scheme(self):
        assert self.keyring.scheme is not None

        # generate keyring
        self.keyring.set_password('system', 'user', 'password')
        config = self.get_config()
        krsetting = escape_for_ini('keyring-setting')
        scheme = escape_for_ini('scheme')
        defscheme = '[Argon2] AES128.GCM'

        # default scheme match
        if self.keyring.aesmode == 'GCM':
            assert config.get(krsetting, scheme) == defscheme

        # invalid AES mode
        config.set(krsetting, scheme, defscheme.replace('GCM', 'XXX'))
        with pytest.raises(ValueError):
            self.keyring._check_scheme(config)

        # compatibility with former scheme format
        config.set(krsetting, scheme, 'PyCryptodome ' + defscheme)
        assert self.keyring._check_scheme(config) == None

        # test with invalid KDF
        config.set(krsetting, scheme, defscheme.replace('Argon2', 'PBKDF2'))
        with pytest.raises(ValueError):
            self.keyring._check_scheme(config)

        # a missing scheme is valid
        config.remove_option(krsetting, scheme)
        self.save_config(config)
        assert self.keyring._check_file() == True

        with pytest.raises(AttributeError):
            self.keyring._check_scheme(config)


@pytest.mark.skipif(not is_crypto_supported(),
                    reason = "Need argon2_cffi and PyCryptodome package")
class TestDefaultCryptFileKeyring(TestCryptFileKeyring):
    """ test default AES mode (GCM) """

@pytest.mark.skipif(not is_crypto_supported(),
                    reason = "Need argon2_cffi and PyCryptodome package")
class TestEAXCryptFileKeyring(TestCryptFileKeyring):
    """ test EAX mode """

@pytest.mark.skipif(not is_crypto_supported(),
                    reason = "Need argon2_cffi and PyCryptodome package")
class TestCCMCryptFileKeyring(TestCryptFileKeyring):
    """ test CCM mode """

@pytest.mark.skipif(not is_crypto_supported(),
                    reason = "Need argon2_cffi and PyCryptodome package")
class TesstOCBCryptFileKeyring(TestCryptFileKeyring):
    """ test OCB mode """


@pytest.mark.parametrize(
    argnames="version",
    argvalues=[(1, 3, 4), (1, 3, 6), (1, 3, 8), (1, 3, 9)],
    ids=lambda version: "no version" if version is None else ".".join(str(segment) for segment in version),
)
@pytest.mark.parametrize(
    argnames="activities",
    argvalues=[
        ["set", "get"],
        ["get", "set"],
    ],
    ids=lambda activities: "_".join(activities),
)
def test_versions(version, activities, monkeypatch, tmp_path):
    version_string = ".".join(str(segment) for segment in version)
    filename = "cp{version_string}.cfg".format(version_string=version_string)
    shutil.copyfile(pathlib.Path(__file__).parent.joinpath(filename), tmp_path.joinpath(filename))

    fake_getpass = mock.Mock(return_value="passwd")
    monkeypatch.setattr(getpass, 'getpass', fake_getpass)

    kr = cryptfile.CryptFileKeyring()
    kr.file_path = tmp_path.joinpath(filename)

    for activity in activities:
        if activity == "get":
            assert kr.get_password("service", "user") == "secret"
        elif activity == "set":
            kr.set_password("test write", "user", "test password")
            assert kr.get_password("test write", "user") == "test password"
        else:
            raise Exception("unexpected activity selection")


def test_new_file(monkeypatch, tmp_path):
    fake_getpass = mock.Mock(return_value="passwd")
    monkeypatch.setattr(getpass, 'getpass', fake_getpass)

    kr = cryptfile.CryptFileKeyring()
    kr.file_path = tmp_path.joinpath("cp_new.cfg")

    kr.set_password("test write", "user", "test password")
    assert kr.get_password("test write", "user") == "test password"
