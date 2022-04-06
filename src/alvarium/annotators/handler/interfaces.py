from abc import ABC, abstractmethod
import datetime
from alvarium.annotators.exceptions import RequestHandlerException

from alvarium.sign.contracts import SignInfo

class RequestHandler(ABC):

    @abstractmethod
    def AddSignatureHeaders(self, ticks: datetime, fields: list[str], keys: SignInfo) -> RequestHandlerException:
        pass