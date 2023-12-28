from abc import ABC
from abc import abstractmethod
import os
import subprocess

class Machine(ABC):

    def __init__(self):
        pass

    @abstractmethod
    def read_register(self, register_name):
        raise Exception("Unimplemented")

    @abstractmethod
    def read_physical_memory(self, physical_address, length):
        raise Exception("Unimplemented")

    @abstractmethod
    def read_virtual_memory(self, virtual_address, length):
        raise Exception("Unimplemented")

