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

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, parseResult):
            return NotImplemented
        return self.seed == __o.seed and self.signature == __o.signature and self.keyid == __o.keyid and self.algorithm == __o.algorithm