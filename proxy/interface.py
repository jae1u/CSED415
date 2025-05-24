from typing import Optional
from dataclasses import dataclass

@dataclass
class Request:
    method: str
    url: str
    header: dict[bytes, bytes]
    req_id: int
    body: Optional[bytes] = None

@dataclass
class Response:
    status_code: int
    url: str
    headers: dict[bytes, bytes]
    req_id: int
    body: Optional[bytes] = None
