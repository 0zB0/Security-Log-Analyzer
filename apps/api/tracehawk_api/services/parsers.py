from abc import ABC, abstractmethod

from tracehawk_api.models.domain import ParsedEvent


class LogParser(ABC):
    parser_name: str
    supported_types: list[str]

    @abstractmethod
    def can_parse(self, sample: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        raise NotImplementedError

