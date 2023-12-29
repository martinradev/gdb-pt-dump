from abc import ABC
from abc import abstractmethod

class Machine(ABC):

    def __init__(self):
        pass

    @abstractmethod
    def read_register(self, register_name):
        raise Exception("Unimplemented")

    @abstractmethod
    def read_physical_memory(self, physical_address, length):
        raise Exception("Unimplemented")

