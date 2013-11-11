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
import hashlib
try:
    import passlib
    from passlib.hash import nthash, lmhash, mysql41, oracle10, mysql323, \
        msdcc, msdcc2
except ImportError:
    err = "\nFailed to import passlib, some algorithms will be disabled\n"
    sys.stderr.write(err)
    sys.stderr.flush()
    passlib = None


class BaseAlgorithm(object):
    '''
    Gives us a single interface to passlib and hashlib
    '''

    _data = None

    def __init__(self, data):
        self._data = data

    def update(self, data):
        if self._data is None:
            self._data = data
        else:
            self._data += data

    def digest(self):
        ''' Overload this method with your algorithm '''
        pass

    def hexdigest(self):
        return self.digest().encode('hex')


class Md2(BaseAlgorithm):

    def digest(self):
        return hashlib.new('md2', self._data).digest()


class Md4(BaseAlgorithm):

    def digest(self):
        return hashlib.new('md4', self._data).digest()


class Lm(BaseAlgorithm):

    def digest(self):
        return lmhash.encrypt(self._data).decode('hex')


class Ntlm(BaseAlgorithm):

    def digest(self):
        return nthash.encrypt(self._data).decode('hex')


class MySql323(BaseAlgorithm):

    def digest(self):
        return mysql323.encrypt(self._data).decode('hex')


class MySql41(BaseAlgorithm):

    def digest(self):
        return mysql41.encrypt(self._data).decode('hex')


class Oracle10(BaseAlgorithm):

    _user = 'SYS'

    def digest(self):
        return oracle10.encrypt(self._data, user=self._user).decode('hex')


class Msdcc(BaseAlgorithm):

    _user = "Administrator"

    def digest(self):
        return msdcc.encrypt(self._data, user=self._user).decode('hex')


class Msdcc2(BaseAlgorithm):

    _user = "Administrator"

    def digest(self):
        return msdcc2.encrypt(self._data, user=self._user).decode('hex')


# Base algorithms
algorithms = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
}

if passlib is not None:
    algorithms['md2'] = Md2
    algorithms['md4'] = Md4
    algorithms['lm'] = Lm
    algorithms['ntlm'] = Ntlm
    algorithms['mysql323'] = MySql323
    algorithms['mysql41'] = MySql41
    algorithms['oracle10'] = Oracle10
    algorithms['msdcc'] = Msdcc
    algorithms['msdcc2'] = Msdcc2

