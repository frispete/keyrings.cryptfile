from __future__ import with_statement

import os
import json

import configparser
from keyring.util import properties

from keyrings.cryptfile import __version__ as version
from keyrings.cryptfile.file import EncryptedKeyring
from keyrings.cryptfile.file_base import decodebytes, encodebytes
from keyrings.cryptfile.escape import escape as escape_for_ini

DEFAULT_TIME_COST = 15
DEFAULT_MEMORY_COST = 2**16     # 64 MB
DEFAULT_PARALLELISM = 2

DEFAULT_AES_MODE = 'GCM'

class ArgonAESEncryption(object):
    """
    AEAD AES encryption (default: GCM) with Argon2 based KDF support
    """
    aesmode = DEFAULT_AES_MODE
    version = version
    file_version = None

    time_cost = DEFAULT_TIME_COST
    memory_cost = DEFAULT_MEMORY_COST
    parallelism = DEFAULT_PARALLELISM

    password_encoding = 'utf-8'

    @properties.NonDataProperty
    def scheme(self):
        return '[Argon2] AES128.' + self.aesmode

    def _create_cipher(self, password, salt, nonce = None):
        """
        Create the cipher object to encrypt or decrypt a payload.
        """
        from argon2.low_level import hash_secret_raw, Type
        from Crypto.Cipher import AES

        aesmode = self._get_mode(self.aesmode)
        if aesmode is None:     # pragma: no cover
            raise ValueError('invalid AES mode: %s' % self.aesmode)

        key = hash_secret_raw(
            secret = password.encode(self.password_encoding),
            salt = salt,
            time_cost = self.time_cost,
            memory_cost = self.memory_cost,
            parallelism = self.parallelism,
            hash_len = 16,
            type = Type.ID)

        return AES.new(key, aesmode, nonce)

    @staticmethod
    def _get_mode(mode = None):
        """
        Return the AES mode, or a list of valid AES modes, if mode == None
        """
        from Crypto.Cipher import AES

        AESModeMap = {
            'CCM': AES.MODE_CCM,
            'EAX': AES.MODE_EAX,
            'GCM': AES.MODE_GCM,
            'OCB': AES.MODE_OCB,
        }

        if mode is None:
            return AESModeMap.keys()
        return AESModeMap.get(mode)



class CryptFileKeyring(ArgonAESEncryption, EncryptedKeyring):
    """
    Encrypted File Keyring Backend, based on AEAD AES encryption with Argon2 KDF
    """
    # specify keyring file
    filename = 'cryptfile_pass.cfg'
    pw_prefix = 'pw:'.encode()

    @properties.ClassProperty
    @classmethod
    def priority(self):
        """
        Applicable for all platforms, where the schemes, that are integrated
        with your environment, does not fit.
        """
        try:
            __import__('argon2.low_level')
        except ImportError:     # pragma: no cover
            raise RuntimeError("argon2_cffi package required")
        try:
            __import__('Crypto.Cipher.AES')
        except ImportError:     # pragma: no cover
            raise RuntimeError("PyCryptodome package required")
        if not json:            # pragma: no cover
            raise RuntimeError("JSON implementation such as simplejson "
                "required.")
        return 2.5

    def encrypt(self, password, assoc = None):
        salt = os.urandom(16)
        cipher = self._create_cipher(self.keyring_key, salt)
        if assoc is not None:
            cipher.update(assoc)
        data, mac = cipher.encrypt_and_digest(password)
        # Serialize salt, encrypted password, mac and nonce in a portable format
        data = dict(salt=salt, data=data, mac=mac, nonce=cipher.nonce)
        for key in data:
            # spare a few bytes: throw away newline from base64 encoding
            data[key] = encodebytes(data[key]).decode()[:-1]
        return json.dumps(data).encode()

    def decrypt(self, password_encrypted, assoc = None):
        # unpack the encrypted payload
        data = json.loads(password_encrypted.decode())
        for key in data:
            data[key] = decodebytes(data[key].encode())
        cipher = self._create_cipher(self.keyring_key, data['salt'], data['nonce'])
        if assoc is not None:
            cipher.update(assoc)
        # throws ValueError in case of failures
        return cipher.decrypt_and_verify(data['data'], data['mac'])

    def _check_scheme(self, config):
        """
        check for a valid scheme

        raise AttributeError if missing
        raise ValueError if not valid
        """
        try:
            scheme = config.get(
                escape_for_ini('keyring-setting'),
                escape_for_ini('scheme'),
            )
        except (configparser.NoSectionError, configparser.NoOptionError):
            raise AttributeError("Encryption scheme missing")

        # extract AES mode
        aesmode = scheme[-3:]
        if aesmode not in self._get_mode():
            raise ValueError("Encryption scheme invalid: %s" % (aesmode))

        # setup AES mode
        self.aesmode = aesmode

        # remove pointless crypto module name
        if scheme.startswith('PyCryptodome '):
            scheme = scheme[13:]

        # check other scheme properties
        if scheme != self.scheme:
            raise ValueError("Encryption scheme mismatch "
                             "(exp.: %s, found: %s)" % (self.scheme, scheme))

    def _check_version(self, config):
        """
        check for a valid version
        an existing scheme implies an existing version as well

        return True, if version is valid, and False otherwise
        """
        try:
            self.file_version = config.get(
                    escape_for_ini('keyring-setting'),
                    escape_for_ini('version'),
            )
        except (configparser.NoSectionError, configparser.NoOptionError):
            return False
        return True
