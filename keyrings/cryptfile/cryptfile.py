from __future__ import with_statement

import os
import json

from keyring.py27compat import configparser
from keyring.util import properties
from keyring.util.escape import escape as escape_for_ini

from keyrings.cryptfile.file import EncryptedKeyring
from keyrings.cryptfile.file_base import decodebytes, encodebytes

__version__ = '1.0'

DEFAULT_TIME_COST = 15
DEFAULT_MEMORY_COST = 2**16     # 64 MB
DEFAULT_PARALLELISM = 2

DEFAULT_AES_MODE = 'GCM'

class ArgonAESEncryption(object):
    """
    AEAD AES encryption (default: GCM) with Argon2 based KDF support
    """
    aesmode = DEFAULT_AES_MODE
    version = __version__
    file_version = None

    time_cost = DEFAULT_TIME_COST
    memory_cost = DEFAULT_MEMORY_COST
    parallelism = DEFAULT_PARALLELISM

    password_encoding = 'utf-8'

    @properties.NonDataProperty
    def scheme(self):
        return 'PyCryptodome [Argon2] AES128.' + self.aesmode

    def _create_cipher(self, password, salt, nonce = None):
        """
        Create the cipher object to encrypt or decrypt a payload.
        """
        from argon2.low_level import hash_secret_raw, Type
        from Crypto.Cipher import AES

        aesmode = self._get_mode(self.aesmode)
        if aesmode is None:
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
        except ImportError:
            raise RuntimeError("argon2_cffi package required")
        try:
            __import__('Crypto.Cipher.AES')
        except ImportError:
            raise RuntimeError("PyCryptodome package required")
        if not json:
            raise RuntimeError("JSON implementation such as simplejson "
                "required.")
        return 2.5

    def encrypt(self, password):
        salt = os.urandom(16)
        cipher = self._create_cipher(self.keyring_key, salt)
        data, mac = cipher.encrypt_and_digest(self.pw_prefix + password)
        # Serialize salt, encrypted password, mac and nonce in a portable format
        data = dict(salt=salt, data=data, mac=mac, nonce=cipher.nonce)
        for key in data:
            data[key] = encodebytes(data[key]).decode()
        return json.dumps(data).encode()

    def decrypt(self, password_encrypted):
        # unpack the encrypted payload
        data = json.loads(password_encrypted.decode())
        for key in data:
            data[key] = decodebytes(data[key].encode())
        cipher = self._create_cipher(self.keyring_key, data['salt'], data['nonce'])
        plaintext = cipher.decrypt_and_verify(data['data'], data['mac'])
        assert plaintext.startswith(self.pw_prefix)
        return plaintext[len(self.pw_prefix):]

    def _check_file(self):
        """
        Check if the file exists and has the expected password reference.
        """
        if not os.path.exists(self.file_path):
            return False
        config = configparser.RawConfigParser()
        config.read(self.file_path)

        # password reference exist
        try:
            config.get(
                escape_for_ini('keyring-setting'),
                escape_for_ini('password reference'),
            )
        except (configparser.NoSectionError, configparser.NoOptionError):
            return False

        # read scheme
        try:
            scheme = config.get(
                escape_for_ini('keyring-setting'),
                escape_for_ini('scheme'),
            )
        except (configparser.NoSectionError, configparser.NoOptionError):
            return False

        # extract AES mode
        aesmode = scheme[-3:]
        if aesmode not in self._get_mode():
            return False

        # setup AES mode
        self.aesmode = aesmode

        if scheme != self.scheme:
            raise ValueError("Encryption scheme mismatch "
                             "(exp.: %s, found: %s)" % (self.scheme, scheme))
        # if scheme exists, a version must exist, too
        try:
            self.file_version = config.get(
                    escape_for_ini('keyring-setting'),
                    escape_for_ini('version'),
            )
        except (configparser.NoSectionError, configparser.NoOptionError):
            return False
        return True
