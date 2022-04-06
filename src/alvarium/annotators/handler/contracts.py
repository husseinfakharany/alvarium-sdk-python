from dataclasses import dataclass

@dataclass
class parseResult:
    """A data class that holds the parsed data"""

    seed: str
    signature: str
    keyid: str
    algorithm: str