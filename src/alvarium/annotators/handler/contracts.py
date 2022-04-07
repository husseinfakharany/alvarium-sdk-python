from dataclasses import dataclass
from enum import Enum
class DerivedComponent(Enum):
    Method = "@method"
    TargetURI = "@target-uri"
    RequestTarget = "@request-target"
    Authority = "@authority"
    Scheme = "@scheme"
    Path = "@path"
    Query = "@query"
    QueryParams = "@query-params"

    def __str__(self) -> str:
        return f'{self.value}'
@dataclass
class parseResult:
    """A data class that holds the parsed data"""

    seed: str
    signature: str
    keyid: str
    algorithm: str

