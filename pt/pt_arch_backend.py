from abc import ABC
from abc import abstractmethod

class PTArchBackend(ABC):

    @abstractmethod
    def get_arch(self):
        pass

    @abstractmethod
    def get_filter_is_writeable(self, has_superuser_filter, has_user_filter):
        pass

    @abstractmethod
    def get_filter_is_not_writeable(self, has_superuser_filter, has_user_filter):
        pass

    @abstractmethod
    def get_filter_is_executable(self, has_superuser_filter, has_user_filter):
        pass

    @abstractmethod
    def get_filter_is_not_executable(self, has_superuser_filter, has_user_filter):
        pass

    @abstractmethod
    def get_filter_is_writeable_or_executable(self, has_superuser_filter, has_user_filter):
        pass

    @abstractmethod
    def get_filter_is_user_page(self, has_superuser_filter, has_user_filter):
        pass

    @abstractmethod
    def get_filter_is_superuser_page(self, has_superuser_filter, has_user_filter):
        pass

    @abstractmethod
    def get_filter_is_read_only_page(self, has_superuser_filter, has_user_filter):
        pass

    @abstractmethod
    def get_filter_is_read_only_page(self, has_superuser_filter, has_user_filter):
        pass

    @abstractmethod
    def get_filter_architecture_specific(self, filter_name, has_superuser_filter, has_user_filter):
        pass

    @abstractmethod
    def parse_tables(self, cache, args):
        pass

    @abstractmethod
    def print_table(self, table):
        pass

    @abstractmethod
    def print_kaslr_information(self, table):
        pass

    @abstractmethod
    def print_stats(self):
        pass

