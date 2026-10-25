from dataclasses import dataclass, field

@dataclass
class Task:
    method: str
    path: str = ""
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    data: dict = field(default_factory=dict)
    files: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)