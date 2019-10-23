import os
import subprocess

from datetime import datetime
from abc import ABC, abstractmethod
from architecture import get_architecture

class File():
    def __init__(self, file_path, data_dir, exec_time=20):
        self._path = os.path.abspath(file_path)
        self._name = os.path.basename(file_path)
        self._dir = os.path.dirname(self._path)
        self._data_dir = data_dir
        self._exec_time = exec_time

        arch_info = get_architecture(file_path)
        self._arch, self._bit, self._endian = arch_info

    @property
    def arch(self):
        return self._arch

    @property
    def bit(self):
        return self._bit

    @property
    def endian(self):
        return self._endian

    @property
    def name(self):
        return self._name

    @property
    def path(self):
        return self._path

    @property
    def dir(self):
        return self._dir

    @property
    def data_dir(self):
        return self._data_dir

    @property
    def exec_time(self):
        return self._exec_time
