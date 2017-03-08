from __future__ import with_statement

import os
import json
import base64

from keyring.util import properties
from .file import EncryptedKeyring

__version__ = '1.0'

DEFAULT_TIME_COST = 15
DEFAULT_MEMORY_COST = 2**16     # 64 MB
DEFAULT_PARALLELISM = 2


class ArgonOCBEncryption(object):
    """
    AES OCB with Argon2 based KDF Encryption support
    """
    scheme = 'Cryptodome [Argon2] AES OCB'
    version = __version__
    file_version = None

    time_cost = DEFAULT_TIME_COST
    memory_cost = DEFAULT_MEMORY_COST
    parallelism = DEFAULT_PARALLELISM

    password_encoding = 'utf-8'

    def _create_cipher(self, password, salt, nonce = None):
        """
        Create the cipher object to encrypt or decrypt a payload.
        """
        from argon2.low_level import hash_secret_raw, Type
        from Crypto.Cipher import AES

        key = hash_secret_raw(
            secret = password.encode(self.password_encoding),
            salt = salt,
            time_cost = self.time_cost,
            memory_cost = self.memory_cost,
            parallelism = self.parallelism,
            hash_len = 16,
            type = Type.ID)

        return AES.new(key, AES.MODE_OCB, nonce)


class CryptFileKeyring(ArgonOCBEncryption, EncryptedKeyring):
    """
    Encrypted File Keyring Backend, based on AES OCB with Argon2 KDF
    """
    # specify keyring file
    filename = 'cryptfile.cfg'
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
            data[key] = base64.encodestring(data[key]).decode()
        return json.dumps(data).encode()

    def decrypt(self, password_encrypted):
        # unpack the encrypted payload
        data = json.loads(password_encrypted.decode())
        for key in data:
            data[key] = base64.decodestring(data[key].encode())
        cipher = self._create_cipher(self.keyring_key, data['salt'], data['nonce'])
        plaintext = cipher.decrypt_and_verify(data['data'], data['mac'])
        assert plaintext.startswith(self.pw_prefix)
        return plaintext[len(self.pw_prefix):]
