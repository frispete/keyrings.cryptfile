1.3.9
=====
Kudos to Kyle Altendorf for this release!

Thank you for finally finding and fixing a nasty issue, that I introduced
by careless syncing with keyrings.alt. See:
https://github.com/frispete/keyrings.cryptfile/commit/ae871c09aec4bb84cab7e756bf25b89c6eb04394#r90506129

- Switch back to a single character assoc joiner '\0' and add backwards
  compatibility support for the intervening versions 1.3.6 through 1.3.8.
  Fixes: https://github.com/frispete/keyrings.cryptfile/issues/15
- Add tests for this change and setup a github CI pipeline.
- Switch to jaraco.classes.properties.

1.3.8
=====
- Apply rename of _escape.py in convert.py as well. Thanks, Justin.
- Fix TestEncryptedFileKeyring.test_wrong_password()
- Relocate tests to keyrings/cryptfile/

1.3.7
=====
- Attempt to fix explicit keyring_key handling

1.3.6
=====
- Merge current versions of file.py, file_base.py with tests from keyrings.alt
- Adopt cryptfile tests to pytest
- Rename _escape.py to escape.py

1.3.5
=====
- Adjust to current keyring testing

1.3.4
=====
- Remove support for Python 2.7 and keyring versions prior to 19.0.0

1.3.3
=====

- Fix showstopper, introduced by 1.3.1 changes

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
