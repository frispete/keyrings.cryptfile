1.3.3
=====

- fix showstopper, introduced by 1.3.1 changes

1.3.2
=====

- Fix PyPI description formatting

1.3.1
=====

- Fix install issues, if keyring isn''t installed beforehand.
  Thanks, Erik.

1.3
===

- Compatibility with keyring 15. Thanks, Niklas.
- Add note about keyring_key. Thanks, Wade.
- Clean up setup.py, fetch version from cryptfile

1.2.1
=====

- Flag markdown readme correctly in setup (for PyPI).

1.2
===

- Keyrings namespace package has switched from pkg_resources
  to pkgutil for native namespace package support. Thanks, Jason.
- adjust copyright year in license
- be more specific about python versions

1.1
===

- improve description and switch to markdown

1.0
===

- python 2&3 compatibility
- improve test coverage
- associate service/userid in MAC
- check file version and encryption scheme
- simple encryption mode conversion tool
- allow all availabel AES AEAD modes (CCM, EAX, GCM and OCB)


0.1
===

- Initial release
