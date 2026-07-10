import asyncio
import shutil
from asyncio.subprocess import PIPE
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel, Field

from tracehawk_api.models.domain import Finding, Incident, ParsedEvent, RawLogLine
from tracehawk_api.services.correlation import correlate_incidents
from tracehawk_api.services.detection import run_detection
from tracehawk_api.services.analysis import EvidenceLine
from tracehawk_api.services.parser_registry import default_parsers
from tracehawk_api.services.parsers import LogParser
from tracehawk_api.services.rules import load_rules


class LiveTailControl:
    def __init__(self) -> None:
        self.paused = False


class LiveSnapshot(BaseModel):
    message_type: str = "snapshot"
    source_id: str
    status: str = "active"
    parser: str | None = None
    raw_line_count: int
    parsed_event_count: int
    finding_count: int
    incident_count: int
    source_error: str | None = None
    latest_line_number: int | None = None
    latest_event: ParsedEvent | None = None
    events: list[ParsedEvent] = Field(default_factory=list)
    evidence: list[EvidenceLine] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)


class LiveFileTailer:
    def __init__(
        self,
        path: Path,
        rules_root: Path,
        *,
        poll_interval_seconds: float = 0.25,
        start_at_end: bool = True,
        parsers: list[LogParser] | None = None,
    ) -> None:
        self.path = path
        self.rules_root = rules_root
        self.poll_interval_seconds = poll_interval_seconds
        self.start_at_end = start_at_end
        self.parsers = parsers or default_parsers()
        self.source_id = _source_id(path)
        self.parser: LogParser | None = None
        self.raw_lines: list[RawLogLine] = []
        self.events: list[ParsedEvent] = []
        self.findings: list[Finding] = []
        self.incidents: list[Incident] = []

    async def snapshots(self, control: LiveTailControl | None = None):
        offset = self.path.stat().st_size if self.start_at_end else 0
        line_number = _count_existing_lines(self.path) if self.start_at_end else 0

        yield self.snapshot(status=_status(control))

        while True:
            if control is not None and control.paused:
                await asyncio.sleep(self.poll_interval_seconds)
                continue

            with self.path.open("r", encoding="utf-8") as file:
                file.seek(offset)
                new_text = file.read()
                offset = file.tell()

            for raw_text in new_text.splitlines():
                if not raw_text.strip():
                    continue
                line_number += 1
                snapshot = self._process_line(line_number, raw_text)
                if snapshot is not None:
                    yield snapshot

            await asyncio.sleep(self.poll_interval_seconds)

    def _process_line(self, line_number: int, raw_text: str) -> LiveSnapshot | None:
        raw_line = RawLogLine(
            id=f"{self.source_id}:line:{line_number}",
            source_id=self.source_id,
            line_number=line_number,
            raw_text=raw_text,
            timestamp_observed=datetime.now(UTC),
            content_hash=sha256(raw_text.encode("utf-8")).hexdigest(),
        )
        self.raw_lines.append(raw_line)

        if self.parser is None:
            self.parser = _select_parser(raw_text, self.parsers)

        if self.parser is None:
            return self.snapshot(latest_line_number=line_number)

        event = self.parser.parse_line(raw_line.id, self.source_id, raw_text)
        if event is None:
            return self.snapshot(latest_line_number=line_number)

        self.events.append(event)
        rules = [
            rule
            for rule in load_rules(self.rules_root)
            if self.parser.parser_name in rule.log_types
        ]
        self.findings = run_detection(rules, self.events)
        self.incidents = correlate_incidents(self.findings, self.events)
        return self.snapshot(latest_line_number=line_number, latest_event=event)

    def snapshot(
        self,
        *,
        status: str = "active",
        latest_line_number: int | None = None,
        latest_event: ParsedEvent | None = None,
    ) -> LiveSnapshot:
        return LiveSnapshot(
            source_id=self.source_id,
            status=status,
            parser=self.parser.parser_name if self.parser else None,
            raw_line_count=len(self.raw_lines),
            parsed_event_count=len(self.events),
            finding_count=len(self.findings),
            incident_count=len(self.incidents),
            latest_line_number=latest_line_number,
            latest_event=latest_event,
            events=self.events,
            evidence=[
                EvidenceLine(
                    id=line.id,
                    line_number=line.line_number,
                    raw_text=line.raw_text,
                    content_hash=line.content_hash,
                )
                for line in self.raw_lines
            ],
            findings=self.findings,
            incidents=self.incidents,
        )


def _select_parser(raw_text: str, parsers: list[LogParser]) -> LogParser | None:
    for parser in parsers:
        if parser.can_parse(raw_text):
            return parser
    return None


class LiveFolderWatcher:
    def __init__(
        self,
        path: Path,
        rules_root: Path,
        *,
        pattern: str = "*.log",
        poll_interval_seconds: float = 0.5,
        start_at_end: bool = True,
        parsers: list[LogParser] | None = None,
    ) -> None:
        self.path = path
        self.rules_root = rules_root
        self.pattern = pattern
        self.poll_interval_seconds = poll_interval_seconds
        self.start_at_end = start_at_end
        self.source_id = _source_id(path)
        self.parsers = parsers or default_parsers()
        self.parser: LogParser | None = None
        self.raw_lines: list[RawLogLine] = []
        self.events: list[ParsedEvent] = []
        self.findings: list[Finding] = []
        self.incidents: list[Incident] = []
        self._offsets: dict[Path, int] = {}
        self._line_numbers: dict[Path, int] = {}

    async def snapshots(self, control: LiveTailControl | None = None):
        self._discover_files()
        yield self.snapshot(status=_status(control))

        while True:
            if control is not None and control.paused:
                await asyncio.sleep(self.poll_interval_seconds)
                continue

            self._discover_files()
            for file_path in sorted(self._offsets):
                for snapshot in self._read_new_lines(file_path):
                    yield snapshot

            await asyncio.sleep(self.poll_interval_seconds)

    def _discover_files(self) -> None:
        for file_path in sorted(self.path.glob(self.pattern)):
            if not file_path.is_file() or file_path in self._offsets:
                continue
            self._offsets[file_path] = file_path.stat().st_size if self.start_at_end else 0
            self._line_numbers[file_path] = _count_existing_lines(file_path) if self.start_at_end else 0

    def _read_new_lines(self, file_path: Path) -> list[LiveSnapshot]:
        snapshots: list[LiveSnapshot] = []
        with file_path.open("r", encoding="utf-8") as file:
            file.seek(self._offsets[file_path])
            new_text = file.read()
            self._offsets[file_path] = file.tell()

        for raw_text in new_text.splitlines():
            if not raw_text.strip():
                continue
            self._line_numbers[file_path] += 1
            snapshot = self._process_line(file_path, self._line_numbers[file_path], raw_text)
            if snapshot is not None:
                snapshots.append(snapshot)
        return snapshots

    def _process_line(self, file_path: Path, line_number: int, raw_text: str) -> LiveSnapshot | None:
        raw_line = RawLogLine(
            id=f"{self.source_id}:{file_path.name}:line:{line_number}",
            source_id=self.source_id,
            line_number=len(self.raw_lines) + 1,
            raw_text=raw_text,
            timestamp_observed=datetime.now(UTC),
            content_hash=sha256(raw_text.encode("utf-8")).hexdigest(),
        )
        self.raw_lines.append(raw_line)

        if self.parser is None:
            self.parser = _select_parser(raw_text, self.parsers)

        if self.parser is None:
            return self.snapshot(latest_line_number=raw_line.line_number)

        event = self.parser.parse_line(raw_line.id, self.source_id, raw_text)
        if event is None:
            return self.snapshot(latest_line_number=raw_line.line_number)

        self.events.append(event)
        rules = [
            rule
            for rule in load_rules(self.rules_root)
            if self.parser.parser_name in rule.log_types
        ]
        self.findings = run_detection(rules, self.events)
        self.incidents = correlate_incidents(self.findings, self.events)
        return self.snapshot(latest_line_number=raw_line.line_number, latest_event=event)

    def snapshot(
        self,
        *,
        status: str = "active",
        latest_line_number: int | None = None,
        latest_event: ParsedEvent | None = None,
    ) -> LiveSnapshot:
        return LiveSnapshot(
            source_id=self.source_id,
            status=status,
            parser=self.parser.parser_name if self.parser else None,
            raw_line_count=len(self.raw_lines),
            parsed_event_count=len(self.events),
            finding_count=len(self.findings),
            incident_count=len(self.incidents),
            latest_line_number=latest_line_number,
            latest_event=latest_event,
            events=self.events,
            evidence=[
                EvidenceLine(
                    id=line.id,
                    line_number=line.line_number,
                    raw_text=line.raw_text,
                    content_hash=line.content_hash,
                )
                for line in self.raw_lines
            ],
            findings=self.findings,
            incidents=self.incidents,
        )


class LiveDockerLogStreamer(LiveFileTailer):
    def __init__(
        self,
        container: str,
        rules_root: Path,
        *,
        tail: str = "0",
        parsers: list[LogParser] | None = None,
    ) -> None:
        self.container = container
        self.tail = tail
        pseudo_path = Path(f"docker-{container}.log")
        super().__init__(
            pseudo_path,
            rules_root,
            start_at_end=False,
            parsers=parsers or default_parsers(),
        )
        self.source_id = f"docker:{container}"

    async def snapshots(self, control: LiveTailControl | None = None):
        yield self.snapshot(status=_status(control))
        process = await asyncio.create_subprocess_exec(
            "docker",
            "logs",
            "--follow",
            "--tail",
            self.tail,
            self.container,
            stdout=PIPE,
            stderr=PIPE,
        )
        line_number = 0
        try:
            while True:
                if control is not None and control.paused:
                    await asyncio.sleep(self.poll_interval_seconds)
                    continue
                if process.stdout is None:
                    break
                raw = await process.stdout.readline()
                if not raw:
                    break
                raw_text = raw.decode("utf-8", errors="replace").rstrip("\n")
                if not raw_text.strip():
                    continue
                line_number += 1
                snapshot = self._process_line(line_number, raw_text)
                if snapshot is not None:
                    yield snapshot
        finally:
            process.terminate()
            await process.wait()


class LiveInterfacePacketStreamer:
    def __init__(
        self,
        interface: str,
        rules_root: Path,
        *,
        capture_filter: str = "ip or ip6",
        tshark_path: str = "tshark",
    ) -> None:
        self.interface = interface
        self.rules_root = rules_root
        self.capture_filter = capture_filter
        self.tshark_path = tshark_path
        self.source_id = f"interface:{interface}"
        self.parser_name = "network_packet"
        self.raw_lines: list[RawLogLine] = []
        self.events: list[ParsedEvent] = []
        self.findings: list[Finding] = []
        self.incidents: list[Incident] = []
        self.source_error: str | None = None

    async def snapshots(self, control: LiveTailControl | None = None):
        if shutil.which(self.tshark_path) is None:
            self.source_error = (
                "tshark was not found. Install Wireshark CLI tools or run TraceHawk on a host "
                "with tshark in PATH."
            )
            yield self.snapshot(status="error")
            return

        yield self.snapshot(status=_status(control))
        process = await asyncio.create_subprocess_exec(
            *self._command(),
            stdout=PIPE,
            stderr=PIPE,
        )
        line_number = 0
        try:
            while True:
                if control is not None and control.paused:
                    await asyncio.sleep(0.25)
                    continue
                if process.stdout is None:
                    break
                raw = await process.stdout.readline()
                if not raw:
                    break
                raw_text = raw.decode("utf-8", errors="replace").rstrip("\n")
                if not raw_text.strip():
                    continue
                line_number += 1
                snapshot = self._process_tshark_line(line_number, raw_text)
                if snapshot is not None:
                    yield snapshot
        finally:
            process.terminate()
            await process.wait()

    def _command(self) -> list[str]:
        command = [
            self.tshark_path,
            "-l",
            "-n",
            "-i",
            self.interface,
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "ipv6.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "udp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-e",
            "frame.protocols",
            "-e",
            "frame.len",
            "-e",
            "_ws.col.Protocol",
            "-e",
            "_ws.col.Info",
        ]
        if self.capture_filter:
            command.extend(["-f", self.capture_filter])
        return command

    def _process_tshark_line(self, line_number: int, raw_text: str) -> LiveSnapshot | None:
        raw_line = RawLogLine(
            id=f"{self.source_id}:packet:{line_number}",
            source_id=self.source_id,
            line_number=line_number,
            raw_text=raw_text,
            timestamp_observed=datetime.now(UTC),
            content_hash=sha256(raw_text.encode("utf-8")).hexdigest(),
        )
        self.raw_lines.append(raw_line)

        event = parse_tshark_fields_line(raw_line.id, self.source_id, raw_text, self.interface)
        if event is None:
            return self.snapshot(latest_line_number=line_number)

        self.events.append(event)
        rules = [
            rule
            for rule in load_rules(self.rules_root)
            if self.parser_name in rule.log_types
        ]
        self.findings = run_detection(rules, self.events)
        self.incidents = correlate_incidents(self.findings, self.events)
        return self.snapshot(latest_line_number=line_number, latest_event=event)

    def snapshot(
        self,
        *,
        status: str = "active",
        latest_line_number: int | None = None,
        latest_event: ParsedEvent | None = None,
    ) -> LiveSnapshot:
        return LiveSnapshot(
            source_id=self.source_id,
            status=status,
            parser=self.parser_name,
            raw_line_count=len(self.raw_lines),
            parsed_event_count=len(self.events),
            finding_count=len(self.findings),
            incident_count=len(self.incidents),
            source_error=self.source_error,
            latest_line_number=latest_line_number,
            latest_event=latest_event,
            events=self.events,
            evidence=[
                EvidenceLine(
                    id=line.id,
                    line_number=line.line_number,
                    raw_text=_packet_evidence_text(line.raw_text, self.interface),
                    content_hash=line.content_hash,
                )
                for line in self.raw_lines
            ],
            findings=self.findings,
            incidents=self.incidents,
        )


def parse_tshark_fields_line(
    raw_line_id: str,
    source_id: str,
    raw_line: str,
    interface: str,
) -> ParsedEvent | None:
    fields = raw_line.split("\t")
    if len(fields) < 13:
        return None

    (
        time_epoch,
        ipv4_source,
        ipv6_source,
        ipv4_destination,
        ipv6_destination,
        tcp_source_port,
        udp_source_port,
        tcp_destination_port,
        udp_destination_port,
        protocols,
        frame_length,
        display_protocol,
        info,
    ) = fields[:13]

    source_ip = _first_field(ipv4_source) or _first_field(ipv6_source)
    destination_ip = _first_field(ipv4_destination) or _first_field(ipv6_destination)
    source_port = _int_or_none(_first_field(tcp_source_port) or _first_field(udp_source_port))
    destination_port = _int_or_none(
        _first_field(tcp_destination_port) or _first_field(udp_destination_port)
    )
    protocol_text = (_first_field(display_protocol) or protocols or "unknown").lower()
    transport_protocol = _transport_protocol(protocol_text, protocols)
    event_time = _timestamp_from_epoch(_first_field(time_epoch))
    packet_length = _int_or_none(_first_field(frame_length))

    if not source_ip and not destination_ip:
        return None

    endpoint = f"{source_ip or '?'}:{source_port or '?'} -> {destination_ip or '?'}:{destination_port or '?'}"
    return ParsedEvent(
        id=f"{raw_line_id}:event",
        source_id=source_id,
        raw_line_id=raw_line_id,
        event_time=event_time,
        event_type="network_packet",
        service=f"interface:{interface}",
        source_ip=source_ip,
        message=f"{transport_protocol.upper()} packet on {interface}: {endpoint}",
        normalized_fields={
            "interface": interface,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "transport_protocol": transport_protocol,
            "packet_length": packet_length,
            "protocols": protocols,
            "display_protocol": _first_field(display_protocol),
            "info": info,
        },
    )


def _packet_evidence_text(raw_line: str, interface: str) -> str:
    event = parse_tshark_fields_line("packet:evidence", f"interface:{interface}", raw_line, interface)
    if event is None:
        return raw_line
    return (
        f"interface={interface} "
        f"proto={event.normalized_fields.get('transport_protocol')} "
        f"{event.source_ip or '?'}:{event.normalized_fields.get('source_port') or '?'} -> "
        f"{event.normalized_fields.get('destination_ip') or '?'}:"
        f"{event.normalized_fields.get('destination_port') or '?'} "
        f"len={event.normalized_fields.get('packet_length') or '?'} "
        f"info={event.normalized_fields.get('info') or ''}"
    ).strip()


def _first_field(value: str | None) -> str | None:
    if not value:
        return None
    first = value.split(",", 1)[0].strip()
    return first or None


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _timestamp_from_epoch(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), UTC)
    except ValueError:
        return None


def _transport_protocol(display_protocol: str, protocols: str) -> str:
    values = f"{display_protocol}:{protocols}".lower()
    if "tcp" in values:
        return "tcp"
    if "udp" in values:
        return "udp"
    if "icmp" in values:
        return "icmp"
    return display_protocol or "unknown"


def _source_id(path: Path) -> str:
    digest = sha256(str(path.resolve()).encode("utf-8")).hexdigest()[:12]
    safe_name = "".join(char if char.isalnum() else "-" for char in path.name.lower()).strip("-")
    return f"live:{safe_name or 'file'}:{digest}"


def _count_existing_lines(path: Path) -> int:
    with path.open("r", encoding="utf-8") as file:
        return sum(1 for line in file if line.strip())


def _status(control: LiveTailControl | None) -> str:
    return "paused" if control is not None and control.paused else "active"
