#!/usr/bin/env python
"""Simple tool to convert cryptfile keyring encryption modes"""

from __future__ import print_function

import os
import sys
import logging
import argparse

log = logging.getLogger('convert')

from keyring.py27compat import configparser
from keyring.util.escape import escape, unescape

from keyrings.cryptfile.cryptfile import CryptFileKeyring

NOTE = """\
Note: no effort has been made to replace the original file.
Please check the new file, and move it over manually.
"""

class CommandLineTool(object):
    def __init__(self):
        self.aesmodes = CryptFileKeyring._get_mode()
        self.parser = argparse.ArgumentParser(
                        usage = '%(prog)s [-h] newmode [infile] [outfile]',
                        epilog = NOTE,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
        self.parser.add_argument('newmode', help = 'new AES mode [one of: %s]' %
                                 ', '.join(self.aesmodes))
        self.parser.add_argument('infile', help = 'File to convert',
                                 nargs = '?', default = None)
        self.parser.add_argument('outfile',
                                 help = 'Converted file [default: infile + pid]',
                                 nargs = '?', default = None)

    def run(self, argv):
        args = self.parser.parse_args(argv)

        inkr = CryptFileKeyring()
        outkr = CryptFileKeyring()

        # prepare infile
        infile = args.infile
        if not infile:
            infile = inkr.file_path
        else:
            inkr.file_path = infile
            inkr.filename = os.path.basename(infile)

        if not os.path.exists(infile):
            self.parser.exit(3, '%s not found\n' % infile)

        if not inkr._check_file():
            self.parser.exit(3, 'Failed to parse %s\n' % infile)

        # prepare infile
        outfile = args.outfile
        if not outfile:
            outfile = infile + '.%d' % os.getpid()

        if os.path.exists(outfile):
            self.parser.exit(3, '%s exists already\n' % outfile)

        outkr.file_path = outfile
        outkr.filename = os.path.basename(outfile)

        # unlock the infile keyring
        inkr.keyring_key

        config = configparser.RawConfigParser()
        config.read(infile)

        log.info('infile %s: %s', infile, inkr.scheme)
        log.info('outfile %s: %s', outfile, outkr.scheme)

        for section in config.sections():
            if section != escape('keyring-setting'):
                for username in config.options(section):
                    username = unescape(username)
                    section = unescape(section)
                    log.info('process: %s.%s', section, username)
                    passwd = inkr.get_password(section, username)
                    if passwd:
                        outkr.set_password(section, username, passwd)
                    else:
                        log.error('invalid entry: [%s]%s', section, username)


def main(argv=None):
    """Main command line interface."""

    logging.basicConfig(level = logging.DEBUG)

    if argv is None:
        argv = sys.argv[1:]

    cli = CommandLineTool()
    try:
        return cli.run(argv)
    except KeyboardInterrupt:
        print('Canceled')
        return 3


if __name__ == '__main__':
    sys.exit(main())
