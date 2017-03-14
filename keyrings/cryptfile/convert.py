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
                        usage = '%(prog)s [-hvkf] aesmode [infile] [outfile]',
                        epilog = NOTE,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
        self.parser.add_argument('aesmode', help = 'new AES mode [one of: %s]' %
                                 ', '.join(self.aesmodes))
        self.parser.add_argument('infile', help = 'File to convert',
                                 nargs = '?')
        self.parser.add_argument('outfile',
                                 help = 'Converted file [default: infile.pid]',
                                 nargs = '?')
        self.parser.add_argument('-v', '--verbose',
                                 help = 'verbose mode (cumulative)',
                                 action = 'count')
        self.parser.add_argument('-k', '--keep',
                                 help = 'keep old password',
                                 action = 'store_true')
        self.parser.add_argument('-f', '--force',
                                 help = 'replace existing outfile',
                                 action = 'store_true')

    def run(self, argv):
        args = self.parser.parse_args(argv)

        self.setup_logging(args.verbose)

        inkr = CryptFileKeyring()
        outkr = CryptFileKeyring()
        outkr.aesmode = args.aesmode

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

        log.info('infile %s: %s', infile, inkr.scheme)

        # prepare infile
        outfile = args.outfile
        if not outfile:
            outfile = infile + '.%d' % os.getpid()

        if os.path.exists(outfile):
            if args.force:
                os.remove(outfile)
                log.info('%s removed', outfile)
            else:
                self.parser.exit(3, '%s exists already\n' % outfile)

        outkr.file_path = outfile
        outkr.filename = os.path.basename(outfile)

        log.info('outfile %s: %s', outfile, outkr.scheme)

        # unlock the infile keyring
        try:
            inkr.keyring_key
        except ValueError as e:
            self.parser.exit(3, 'Unlock %s: %s\n' % (infile, e))

        if args.keep:
            outkr._get_new_password = lambda: inkr.keyring_key
        else:
            outkr.keyring_key

        config = configparser.RawConfigParser()
        config.read(infile)

        for section in config.sections():
            log.debug('process section: %s', section)
            if section != escape('keyring-setting'):
                for username in config.options(section):
                    username = unescape(username)
                    section = unescape(section)
                    log.info('process: %s.%s', section, username)
                    password = inkr.get_password(section, username)
                    if password:
                        outkr.set_password(section, username, password)
                        log.debug('%s.%s: %s', section, username,  password)
                    else:
                        log.error('invalid entry: [%s]%s', section, username)

        return 0

    def setup_logging(self, verbose):
        for idx, loglevel in enumerate(range(logging.WARNING,
                                             logging.NOTSET,
                                             -10)):
            if idx == verbose:
                break
        logging.basicConfig(level = loglevel)


def main(argv=None):
    """Main command line interface."""
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
