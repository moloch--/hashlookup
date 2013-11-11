#!/usr/bin/env python
'''
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
---------------------------------------------------------------------
The first step in creating a cryptographic hash lookup table.
Creates a file of the following format:

    [HASH_PART][WORDLIST_OFFSET][HASH_PART][WORDLIST_OFFSET]...

HASH_PART is the first 64 BITS of the hash, right-padded with zeroes if
necessary.  WORDLIST_OFFSET is the position of the first character of the
word in the dictionary encoded as a 48-bit LITTLE ENDIAN integer.
'''


import sys
import time
import struct
import hashlib
import argparse
import threading
import platform

from os import _exit
from os.path import exists, isfile

try:
    from Algorithms import algorithms
except ImportError:
    sys.stderr.write("Missing file Algorithms.py")
    _exit(2)

if platform.system().lower() in ['linux', 'darwin']:
    W = "\033[0m"  # default/white
    R = "\033[31m"  # red
    P = "\033[35m"  # purple
    C = "\033[36m"  # cyan
    O = "\033[33m"
    bold = "\033[1m"
    clear = chr(27) + '[2K\r'
else:
    bold = W = R = P = C = O = ""
    clear = '\n'

INFO = bold + C + "[*] " + W
WARN = bold + R + "[!] " + W
MONEY = bold + O + "[$] " + W
PROMPT = bold + P + "[?] " + W

<<<<<<< Updated upstream

def create_index(fword, fout, algo):
=======
def create_index(fword, fout, algorithm, flock):
    ''' Create an index and write to file '''
>>>>>>> Stashed changes
    position = fword.tell()
    line = fword.readline()
    while line:
        word = line.strip('\r\n')
        fdigest = algorithm(word).digest()[:8]  # Only take first 64bits of hash
        fpos = struct.pack('<Q', position)[:6]  # Get 48bit int in little endian
        fout.write("%s%s" % (fdigest, fpos))
        position = fword.tell()
        line = fword.readline()

<<<<<<< Updated upstream
def display_status(fin, fout):
=======
def display_status(fword, fout, flock):
    ''' Display status / progress '''
>>>>>>> Stashed changes
    try:
        megabyte = (1024.0 ** 2.0)
        fpath = os.path.abspath(fword.name)
        size = os.path.getsize(fpath) / megabyte
        sys.stdout.write(INFO + 'Reading %s ...\n' % fpath)
<<<<<<< Updated upstream
        while not fin.closed and not fout.closed:
            mb_pos = float(fin.tell() / megabyte)
            sys.stdout.write(clear)
            sys.stdout.write(INFO + '%.2f Mb of %.2f Mb' % (mb_pos, size))
            sys.stdout.write(' (%3.2f%s) ->' % ((100.0 * (mb_pos / size)), '%',))
            sys.stdout.write(' %.2f Mb' % float(fout.tell() / megabyte))
=======
        while not fword.closed and not fout.closed:
            flock.acquire()
            fword_pos = float(fword.tell() / megabyte)
            fout_post = fout.tell()
            flock.release()
            sys.stdout.write(clear)
            sys.stdout.write(INFO + '%.2f Mb of %.2f Mb' % (fword_pos, size))
            sys.stdout.write(' (%3.2f%s) ->' % ((100.0 * (fword_pos / size)), '%',))
            sys.stdout.write(' "%s" (%.2f Mb)' % (fout.name, float(fout_pos / megabyte)))
>>>>>>> Stashed changes
            sys.stdout.flush()
            time.sleep(0.25)
    except:
        return  # Clean exit if we throw an exception

<<<<<<< Updated upstream
def main(args):
    fword = open(args.wordlist, 'rb')
    fout = open(args.fout, 'wb')
=======

def get_algorithms(args):
    ''' Returns a list of valid algorithms passed in by the cli '''
    if 'all' in args.algorithms:
        return [algorithms[name] for name in algorithms.keys()]
    else:
        names = filter(lambda algo: algo in algorithms, args.algorithms)
        return [algorithms[name] for name in names]


def index_wordlist(fword, fout, algorithm, flock):
>>>>>>> Stashed changes
    try:
        thread = threading.Thread(target=display_status, args=(fword, fout,))
        thread.start()
<<<<<<< Updated upstream
        create_index(fword, fout, args.algorithm)
=======
        create_index(fword, fout, algorithm, flock)
>>>>>>> Stashed changes
    except KeyboardInterrupt:
        sys.stdout.write(clear)
        sys.stdout.write(WARN + 'User requested stop ...\n')
        return
    finally:
        fout.close()
        fword.close()
        thread.join()


<<<<<<< Updated upstream
=======
def main(args):
    flock = threading.Lock()
    for algo in get_algorithms(args):
        fword = open(args.wordlist, 'rb')
        fout_name = args.fout + '-%s.idx' % algo.key
        mode = 'wb'
        if exists(fout_name) and isfile(fout_name):
            prompt = raw_input(PROMPT+'File exist %s! [w/a/skip]: ' % fout_name)
            mode = 'ab' if prompt.lower() == 'a' else None
        if mode is not None:
            fout = open(fout_name, mode)
            index_wordlist(fword, fout, algo, flock)
    sys.stdout.write(clear)
    sys.stdout.write(MONEY + 'All Done.\n')


>>>>>>> Stashed changes
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Create unsorted IDX files',
    )
    parser.add_argument('-v', '--version',
        action='version',
        version='Create IDX 0.1.1',
    )
    parser.add_argument('-w',
        dest='wordlist',
        help='index passwords from text file',
        required=True,
    )
    parser.add_argument('-a',
        nargs='*',
        dest='algorithms',
        help='hashing algorithm to use: %s' % (['all']+ algorithms.keys()),
        required=True,
    )
    parser.add_argument('-o',
        dest='fout',
        help='output file to write data to',
    )
    args = parser.parse_args()
    if exists(args.wordlist) and isfile(args.wordlist):
        if args.fout is None:
            args.fout = args.wordlist[:args.wordlist.rfind('.')]
        main(args)
    else:
        sys.stdout.write('Wordlist path does not exist, or is not file')
