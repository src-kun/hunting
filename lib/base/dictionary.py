#!/usr/bin/python3  
# -*- coding: utf-8 -*-  
#
# @Time    : 2019-08-19 14:41
# @Author  : Mauro Soria
# @FileName: dictionary.py
# @Software: PyCharm

#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

import threading

import urllib.error
import urllib.parse
import urllib.request

from lib.utils.file import File
from oset import *


class Dictionary(object):

    def __init__(self, path, extensions=None, lowercase=False, forcedExtensions=False):
        self.entries = []
        self.currentIndex = 0
        self.condition = threading.Lock()
        self._extensions = []
        if extensions:
            if isinstance(extensions, str):
                self._extensions.append(extensions)
            elif isinstance(extensions, list):
                self._extensions = extensions
            else:
                raise Exception('TODO: extensions type error!')
        self._path = path
        self._forcedExtensions = forcedExtensions
        self.lowercase = lowercase
        self.dictionaryFile = File(self.path)
        self.generate()

    @property
    def extensions(self):
        return self._extensions

    @extensions.setter
    def extensions(self, value):
        self._extensions = value

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, path):
        self._path = path

    @classmethod
    def quote(cls, string):
        return urllib.parse.quote(string, safe=":/~?%&+-=$")

    """
    Dictionary.generate() behaviour

    Classic dirsearch wordlist:
      1. If %EXT% keyword is present, append one with each extension REPLACED.
      2. If the special word is no present, append line unmodified.

    Forced extensions wordlist (NEW):
      This type of wordlist processing is a mix between classic processing
      and DirBuster processing.
          1. If %EXT% keyword is present in the line, immediately process as "classic dirsearch" (1).
          2. If the line does not include the special word AND is NOT terminated by a slash,
            append one with each extension APPENDED (line.ext) and ONLYE ONE with a slash.
          3. If the line does not include the special word and IS ALREADY terminated by slash,
            append line unmodified.
    """

    def generate(self):
        result = []
        for line in self.dictionaryFile.getLines():

            # Skip comments
            if line.lstrip().startswith("#"):
                continue

            # No extensions
            if self._extensions is None:
                result.append(self.quote(line))

            # Classic dirsearch wordlist processing (with %EXT% keyword)
            elif '%EXT%' in line or '%ext%' in line:
                for extension in self._extensions:
                    if '%EXT%' in line:
                        newline = line.replace('%EXT%', extension)

                    if '%ext%' in line:
                        newline = line.replace('%ext%', extension)

                    quote = self.quote(newline)
                    result.append(quote)

            # If forced extensions is used and the path is not a directory ... (terminated by /)
            # process line like a forced extension.
            elif self._forcedExtensions and not line.rstrip().endswith("/"):
                quoted = self.quote(line)

                for extension in self._extensions:
                    # Why? check https://github.com/maurosoria/dirsearch/issues/70
                    if extension.strip() == '':
                        result.append(quoted)
                    else:
                        result.append(quoted + '.' + extension)

                if quoted.strip() not in ['']:
                    result.append(quoted + "/")
            else:
                # Append line unmodified.
                result.append(self.quote(line))

        # oset library provides inserted ordered and unique collection.
        if self.lowercase:
            self.entries = list(oset(map(lambda l: l.lower(), result)))

        else:
            self.entries = list(oset(result))

        del (result)

    def regenerate(self):
        self.generate(lowercase=self.lowercase)
        self.reset()

    def nextWithIndex(self, basePath=None):
        self.condition.acquire()

        try:
            result = self.entries[self.currentIndex]

        except IndexError:
            self.condition.release()
            raise StopIteration

        self.currentIndex = self.currentIndex + 1
        currentIndex = self.currentIndex
        self.condition.release()
        return currentIndex, result

    def __next__(self, basePath=None):
        _, path = self.nextWithIndex(basePath)
        return path

    def reset(self):
        self.condition.acquire()
        self.currentIndex = 0
        self.condition.release()

    def __len__(self):
        return len(self.entries)
