Summary
-------

Encrypted plain file keyring backend for use with the
[keyring](https://pypi.python.org/pypi/keyring)  package.

Description
-----------
The project is mainly targeted on a sufficiently secure storage for plain text
passwords (keyring) in a simple portable file, where the default keyring storage
implementation of a usual desktop environment doesn't fit.

Cryptography
------------
The keyring is secured with a keyring password. A raw
`Argon2($argon2id$v=19$m=65536,t=15,p=2)` hash is generated from the keyring
password, which is used as a key for encryption of plaintext passwords in one of
the supported authenticated AES encryption schemes (CCM, EAX, GCM, OCB), where
GCM is the default. The resulting encrypted data is persisted, together with the
Argon2 salt, nonce and MAC. This value is stored with a service/userid reference
in a text file (.ini format). The service/userid is taken into account as
associated data for MAC calculation.

Initially, a static reference value, treated as a password is stored as well,
and this value is used for verification of the keyring password in subsequent
accesses.

Attack surface
--------------
The static reference value allow some form of attack, as it encrypts a well
known value. Hopefully, the Argon2 hash, combined with the authenticated AES
encryption scheme raises the effort to break the key sufficiently high.

The Argon2 parameterization is chosen in a way, that usual desktop and server
systems as of today (2017) have to process a significant CPU and Memory load
in order to calculate the hashes, which renders brute force attacks impractical.

The authenticated AES encryption scheme prevents tampering with the encrypted
data as well as its reference (service/userid).

Quick start guide
-----------------

In order to get you started, you will need to have a `python3` environment
and `git` available (preferably on a linux system).

You might want to provide the python packages [argon2-cffi](https://pypi.python.org/pypi/argon2_cffi), [keyring](https://pypi.python.org/pypi/keyring), [pycryptodome](https://pypi.python.org/pypi/pycryptodome)
and their dependencies (most notably [SecretStorage](https://pypi.python.org/pypi/SecretStorage) and [cryptography](https://pypi.python.org/pypi/cryptography)) with your
system package management, or use a local venv, but that will depend on a
properly working C compiler and some development packages installed
(`python-devel` and `openssl-devel` at least).

Setup package and environment
-----------------------------

```
$ git clone https://github.com/frispete/keyrings.cryptfile
$ cd keyrings.cryptfile
$ pyvenv env
$ . env/bin/activate
(env) $ pip install -e .
```

The last command should succeed without errors, some development packages might
be missing otherwise.

Example session
---------------

Create an encrypted keyring, and store a test password into it. The process asks
for the keyring password itself, that protects your stored keyring values.

```
(env) $ python3
Python 3.4.5 (default, Jul 03 2016, 12:57:15) [GCC] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from keyrings.cryptfile.cryptfile import CryptFileKeyring
>>> kr = CryptFileKeyring()
>>> kr.set_password("service", "user", "secret")
Please set a password for your new keyring: ******
Please confirm the password: ******
>>> ^d
```

Now retrieve the stored secret from the keyring again:

```
(env) $ python3
Python 3.4.5 (default, Jul 03 2016, 12:57:15) [GCC] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from keyrings.cryptfile.cryptfile import CryptFileKeyring
>>> kr = CryptFileKeyring()
>>> kr.get_password("service", "user")
Please enter password for encrypted keyring: ******
'secret'
>>> ^d
```

Note, that the KDF delays the `{set,get}_password()` operations for a few seconds
(~1 sec. on a capable system).

Result
------

The resulting file might look similar to:
```
(env) $ cat ~/.local/share/python_keyring/cryptfile_pass.cfg
[keyring_2Dsetting]
password_20reference =
    eyJtYWMiOiAiWmVHU2lBalZ5WHd6Vmg3K2Z6TGx2UT09IiwgIm5vbmNlIjogIjB0b2dKa3RYdmdY
    TVpEU1F1QkFOZFE9PSIsICJzYWx0IjogInZ2dFYzN2JvWnVLRTQzVHJ6dGd6YVE9PSIsICJkYXRh
    IjogIk1UdnRzYUZ6OHdSaUZYbFBHOWZmL2dQZ0dmL3ROOG05In0=
scheme = [Argon2] AES128.GCM
version = 1.0

[service]
user =
    eyJtYWMiOiAiaTJ4MWhNVGJ1S0pTZExYSXQwR0dqUT09IiwgIm5vbmNlIjogIlJ5YU1DZmkyZ0JE
    NStlNHN6MGpQRWc9PSIsICJzYWx0IjogIjlIM1hJbDVhZmRZaVhkTUZyTWNOV2c9PSIsICJkYXRh
    IjogImhNVC9LaTRYIn0=
```

The values can be decoded like this:

```
(env) $ python3
>>> import base64
>>> base64.decodebytes(b"""
... eyJtYWMiOiAiaTJ4MWhNVGJ1S0pTZExYSXQwR0dqUT09IiwgIm5vbmNlIjogIlJ5YU1DZmkyZ0JE
... NStlNHN6MGpQRWc9PSIsICJzYWx0IjogIjlIM1hJbDVhZmRZaVhkTUZyTWNOV2c9PSIsICJkYXRh
... IjogImhNVC9LaTRYIn0=""")
b'{"mac": "i2x1hMTbuKJSdLXIt0GGjQ==",
   "nonce": "RyaMCfi2gBD5+e4sz0jPEg==",
    "salt": "9H3XIl5afdYiXdMFrMcNWg==",
    "data": "hMT/Ki4X"}'
```

Discussion
----------

The items of the json dict constitute the encryption parameters and value. In
theory, it should be sufficiently **hard** to get back to the plain value of
**data** without knowledge of the password. Due to the association of the values
reference (`service` and `user` here) with the authenticated encryption,
modifications of values reference are detected/rejected as well.

The class hierarchy is inherited from the keyrings.alt project, which is not
exactly easy to follow. The most interesting parts are in
*keyrings/cryptfile/cryptfile.py*, which is quite concise itself, even if you're
not fluent in python.

In order to control this process any further, you might want to subclass
`CryptFileKeyring` and/or `PlaintextKeyring`.

Notes
-----

You can avoid the interactive getpass() request for the keyring password by
supplying `kr.keyring_key = "your keyring password"` before calling any other
methods on the keyring. The following example shows a simple way to retrieve the 
password from an environment variable `KEYRING_CRYPTFILE_PASSWORD`, when present:
```python
from getpass import getpass
from os import getenv
from keyrings.cryptfile.cryptfile import CryptFileKeyring
kr = CryptFileKeyring()
kr.keyring_key = getenv("KEYRING_CRYPTFILE_PASSWORD") or getpass()
keyring.set_keyring(kr)
```

Testing
-------

Testing is done with pytest as usual. Just executing `pytest` should do the trick.
A verbose test run is performed with `pytest -v`, while a single test is selected
with `pytest -vk test_wrong_password`.

Feedback is always welcome.
