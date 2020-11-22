# -*- coding: utf8 -*-
# vim:set et ts=8 sw=4:

import io
import setuptools
from keyrings.cryptfile import __version__ as version

with io.open('README.md', encoding='utf-8') as readme:
    long_description = readme.read()
    long_description_content_type = 'text/markdown'


name = 'keyrings.cryptfile'
description = 'Encrypted file keyring backend'

setup_params = dict(
    name = name,
    version = version,
    author = 'Hans-Peter Jansen',
    author_email = 'hpj@urpla.net',
    description = description or name,
    long_description = long_description,
    long_description_content_type = long_description_content_type,
    url = 'https://github.com/frispete/' + name,
    license = 'MIT',
    packages = setuptools.find_packages(exclude=['tests']),
    include_package_data = True,
    python_requires = '>=3.5',
    install_requires = [
        'argon2_cffi',
        'keyring>=20.0.0',
        'pycryptodome',
    ],
    extras_require = {},
    setup_requires = [],
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'
    ],
    entry_points = {
        'keyring.backends': [
            'cryptfile = keyrings.cryptfile.cryptfile',
        ],
        'console_scripts': [
            'cryptfile-convert = keyrings.cryptfile.convert:main',
        ],
    },
)

if __name__ == '__main__':
    setuptools.setup(**setup_params)
