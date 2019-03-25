"""Simple tool to convert cryptfile keyring encryption modes"""

from __future__ import print_function

import os
import sys
import logging
import argparse

log = logging.getLogger('convert')

import configparser

from keyrings.cryptfile.cryptfile import CryptFileKeyring
from keyrings.cryptfile._escape import escape, unescape

NOTE = """\
Note: no effort has been made to replace the original keyring file.
Please check the new keyring file, and rename it manually.

If outfile exists already, it is preserved as outfile~.

Default infile:
%s
""" % CryptFileKeyring().file_path

class CommandLineTool(object):
    def __init__(self):
        self.aesmodes = CryptFileKeyring._get_mode()
        self.parser = argparse.ArgumentParser(
                        usage = '%(prog)s [-hvk] aesmode [infile] [outfile]',
                        epilog = NOTE,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
        self.parser.add_argument('aesmode', help = 'new AES mode [one of: %s]' %
                                                   ', '.join(self.aesmodes))
        self.parser.add_argument('infile',
                                 help = 'Keyring file to convert',
                                 nargs = '?')
        self.parser.add_argument('outfile',
                                 help = 'New keyring file [default: infile.pid]',
                                 nargs = '?')
        self.parser.add_argument('-v', '--verbose',
                                 help = 'verbose mode (cumulative)',
                                 action = 'count')
        self.parser.add_argument('-k', '--keep',
                                 help = 'keep old password',
                                 action = 'store_true')

    def run(self, argv):
        # parse args, setup logging and prepare keyrings
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
            self.errexit('%s not found' % infile)
        if not inkr._check_file():
            self.errexit('Failed to parse %s' % infile)
        log.info('infile %s: %s', infile, inkr.scheme)

        # prepare outfile
        outfile = args.outfile
        if not outfile:
            outfile = infile + '.%d' % os.getpid()
        if os.path.exists(outfile):
            if os.path.samefile(infile, outfile):
                self.errexit('infile and outfile must NOT be the same file')
            # outfile exists: rename
            os.rename(outfile, outfile + '~')
            log.info('%s renamed to %s~', outfile, outfile)
        outkr.file_path = outfile
        outkr.filename = os.path.basename(outfile)
        log.info('outfile %s: %s', outfile, outkr.scheme)

        # unlock the infile keyring
        try:
            inkr.keyring_key
        except ValueError as e:
            self.errexit('Unlock %s: %s' % (infile, e))

        # keep old password or request password for new keyring
        if args.keep:
            outkr._get_new_password = lambda: inkr.keyring_key
        else:
            outkr.keyring_key

        # process infile
        config = configparser.RawConfigParser()
        config.read(infile)
        for section in config.sections():
            log.debug('process section: [%s]', section)
            if section != escape('keyring-setting'):
                for username in config.options(section):
                    username = unescape(username)
                    section = unescape(section)
                    log.info('process: [%s] %s', section, username)
                    password = inkr.get_password(section, username)
                    if password:
                        outkr.set_password(section, username, password)
                        log.debug('[%s] %s: %s', section, username,  password)
                    else:
                        log.error('invalid entry: [%s]%s', section, username)

        return 0

    def errexit(self, msg, retcode = 1):
        log.error(msg)
        sys.exit(retcode)

    def setup_logging(self, verbose):
        for idx, loglevel in enumerate(range(logging.WARNING,
                                             logging.NOTSET,
                                             -10)):
            if idx == verbose:
                break
        logging.basicConfig(
            level = loglevel,
            format = '%(asctime)s %(levelname)5s: %(message)s',
            datefmt = '%Y-%m-%d %H:%M:%S',
        )


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
