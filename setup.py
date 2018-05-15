# -*- coding: utf8 -*-
# vim:set et ts=8 sw=4:

import io

import setuptools

with io.open('README.md', encoding='utf-8') as readme:
    long_description = readme.read()


name = 'keyrings.cryptfile'
description = 'Encrypted file keyring backend'

setup_params = dict(
    name = name,
    #use_scm_version = True,
    version = '1.2',
    author = 'Hans-Peter Jansen',
    author_email = 'hpj@urpla.net',
    description = description or name,
    long_description = long_description,
    url = 'https://github.com/frispete/' + name,
    license = 'MIT',
    packages = setuptools.find_packages(exclude=['tests']),
    include_package_data = True,
    python_requires = '>=2.7',
    install_requires = [
        'argon2_cffi',
        'keyring',
        'pycryptodome',
    ],
    extras_require = {
    },
    setup_requires = [
        #'setuptools_scm>=1.15.0',
    ],
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
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
