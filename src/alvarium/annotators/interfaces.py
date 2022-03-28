from abc import ABC, abstractmethod
import datetime
from alvarium.annotators.exceptions import RequestHandlerException

from alvarium.contracts.annotation import Annotation
from alvarium.sign.contracts import SignInfo
from alvarium.utils import PropertyBag

class Annotator(ABC):
    """A unit responsible for annontating raw data and producing an Annotation object"""

    @abstractmethod
    def execute(self, data:bytes, ctx: PropertyBag = None) -> Annotation:
        pass

class RequestHandler(ABC):

    @abstractmethod
    def AddSignatureHeaders(self, ticks: datetime, fields: list[str], keys: SignInfo) -> RequestHandlerException:
        pass