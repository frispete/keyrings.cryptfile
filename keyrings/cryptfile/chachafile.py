from __future__ import with_statement

import os
import json

import configparser
import sys

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import getpass
from keyring.util import properties

from keyrings.cryptfile import __version__ as version
from keyrings.cryptfile.file import EncryptedKeyring
from keyrings.cryptfile.file_base import decodebytes, encodebytes
from keyrings.cryptfile.escape import escape as escape_for_ini


class ChaCha20Encryption:
    """
    AEAD encryption based on ChaChaPoly3105
    """
    version = version
    file_version = None
    password_encoding = 'utf-8'

    @properties.NonDataProperty
    def scheme(self):
        return '[ChaCha20Poly1305]'

    def _create_cipher(self, key):
        """
        Create the cipher object to encrypt or decrypt a payload.
        """
        if not self._cipher:
            self._cipher = ChaCha20Poly1305(key.encode(self.password_encoding))
        return self._cipher


class ChaChaFileKeyring(ChaCha20Encryption, EncryptedKeyring):
    """
    Encrypted File Keyring Backend, based on AEAD ChaCha20 encryption.
    For performance reasons, password is expected to be 32 bytes of
    random data. No KDF transformation is applied to the password.
    """
    # specify keyring file
    filename = 'chachafile_pass.cfg'
    pw_prefix = 'pw:'.encode()

    def __init__(self):
        super().__init__()
        self._cipher = None

    @properties.ClassProperty
    @classmethod
    def priority(self):
        """
        Applicable for all platforms, where the schemes, that are integrated
        with your environment, do not fit.
        """
        try:
            ChaCha20Poly1305(b'Q5V8yInhsWn6UIKYGmQwxZRc07NfWATu')
        except UnsupportedAlgorithm:     # pragma: no cover
            raise RuntimeError("ChaCha20Poly1305 is not supported by this version of OpenSSL")

        return 1.0

    def encrypt(self, password, assoc=None):
        nonce = os.urandom(12)
        cipher = self._create_cipher(self.keyring_key)
        data = cipher.encrypt(nonce, password, assoc)
        # Serialize data and nonce in a portable format
        data = dict(data=data, nonce=nonce)
        for key in data:
            # spare a few bytes: throw away newline from base64 encoding
            data[key] = encodebytes(data[key]).decode()[:-1]
        return json.dumps(data).encode()

    def decrypt(self, password_encrypted, assoc=None):
        # unpack the encrypted payload
        data = json.loads(password_encrypted.decode())
        for key in data:
            data[key] = decodebytes(data[key].encode())
        cipher = self._create_cipher(self.keyring_key)
        return cipher.decrypt(data['nonce'], data['data'], assoc)

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

    def _get_new_password(self):
        while True:
            key = getpass.getpass("Please set a 32 byte key for your new keyring: ")
            confirm = getpass.getpass('Please confirm the key: ')
            if key != confirm:  # pragma: no cover
                sys.stderr.write("Error: Your key didn't match.\n")
                continue
            if '' == key.strip():  # pragma: no cover
                sys.stderr.write("Error: blank key isn't allowed.\n")
                continue
            if len(key) != 32:  # pragma: no cover
                sys.stderr.write("Error: key must be 32 bytes.\n")
            return key
