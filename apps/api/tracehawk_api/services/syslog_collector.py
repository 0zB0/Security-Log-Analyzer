from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tracehawk_api.database import SessionLocal, init_db
from tracehawk_api.services.analysis import analyze_text
from tracehawk_api.services.correlation_patterns import (
    default_correlation_pattern_path,
    load_correlation_patterns,
)
from tracehawk_api.services.ingest import build_raw_lines_from_text
from tracehawk_api.services.persistence import persist_analysis
from tracehawk_api.services.rules import load_rules


class SyslogCollectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bind_host: str = "127.0.0.1"
    udp_port: int = Field(default=5514, ge=0, le=65535)
    tcp_port: int = Field(default=5514, ge=0, le=65535)
    enable_udp: bool = True
    enable_tcp: bool = True
    allow_remote_bind: bool = False
    max_line_bytes: int = Field(default=8192, ge=128, le=1_000_000)
    queue_size: int = Field(default=1000, ge=1, le=1_000_000)
    max_connections: int = Field(default=32, ge=1, le=10_000)
    idle_timeout_seconds: float = Field(default=30.0, gt=0, le=3600)
    batch_size: int = Field(default=100, ge=1, le=100_000)
    flush_interval_seconds: float = Field(default=1.0, gt=0, le=300)

    @model_validator(mode="after")
    def validate_listener_boundary(self) -> "SyslogCollectorConfig":
        if not self.enable_udp and not self.enable_tcp:
            raise ValueError("At least one syslog transport must be enabled.")
        if not self.allow_remote_bind and not _is_loopback_host(self.bind_host):
            raise ValueError(
                "Remote syslog bind refused. Use a loopback address or explicitly allow it."
            )
        return self


@dataclass(frozen=True)
class SyslogEnvelope:
    protocol: Literal["udp", "tcp"]
    text: str
    peer: str
    received_at: datetime


@dataclass
class SyslogCollectorStats:
    udp_datagrams_received: int = 0
    udp_lines_received: int = 0
    tcp_connections_accepted: int = 0
    tcp_connections_rejected: int = 0
    tcp_lines_received: int = 0
    active_connections: int = 0
    accepted_lines: int = 0
    dropped_queue_full: int = 0
    dropped_oversize: int = 0
    dropped_malformed: int = 0
    idle_timeouts: int = 0
    transport_errors: int = 0
    persisted_batches: int = 0
    persisted_lines: int = 0
    failed_batches: int = 0
    last_analysis_id: str | None = None
    last_error: str | None = None


BatchSink = Callable[[list[SyslogEnvelope], int], str | None]


class SyslogCollector:
    def __init__(
        self,
        config: SyslogCollectorConfig,
        rules_root: Path,
        *,
        batch_sink: BatchSink | None = None,
    ) -> None:
        self.config = config
        self.rules_root = rules_root
        self.stats = SyslogCollectorStats()
        self.queue: asyncio.Queue[SyslogEnvelope] = asyncio.Queue(
            maxsize=config.queue_size
        )
        self.udp_port: int | None = None
        self.tcp_port: int | None = None
        self._batch_sink = batch_sink or self._persist_batch
        self._uses_default_sink = batch_sink is None
        self._rule_library = load_rules(rules_root) if self._uses_default_sink else []
        self._correlation_patterns = (
            load_correlation_patterns(
                default_correlation_pattern_path(rules_root), self._rule_library
            )
            if self._uses_default_sink
            else []
        )
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.Server | None = None
        self._worker_task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self._writers: set[asyncio.StreamWriter] = set()
        self._batch_number = 0
        self._session_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")

    async def start(self) -> None:
        if self._worker_task is not None:
            raise RuntimeError("Syslog collector is already started.")
        if self._uses_default_sink:
            await asyncio.to_thread(init_db)

        self._stopping.clear()
        self._worker_task = asyncio.create_task(self._batch_worker())
        loop = asyncio.get_running_loop()
        try:
            if self.config.enable_udp:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _SyslogDatagramProtocol(self),
                    local_addr=(self.config.bind_host, self.config.udp_port),
                )
                self._udp_transport = transport
                self.udp_port = int(transport.get_extra_info("sockname")[1])
            if self.config.enable_tcp:
                self._tcp_server = await asyncio.start_server(
                    self._handle_tcp,
                    self.config.bind_host,
                    self.config.tcp_port,
                    limit=self.config.max_line_bytes + 1,
                )
                sockets = self._tcp_server.sockets or []
                self.tcp_port = int(sockets[0].getsockname()[1]) if sockets else None
        except Exception:
            await self.stop()
            raise

    async def stop(self) -> None:
        self._stopping.set()
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None

        writers = list(self._writers)
        for writer in writers:
            writer.close()
        if writers:
            await asyncio.gather(
                *(writer.wait_closed() for writer in writers),
                return_exceptions=True,
            )

        if self._worker_task is not None:
            await self._worker_task
            self._worker_task = None

    def submit_udp_datagram(self, payload: bytes, peer: str = "unknown") -> None:
        self.stats.udp_datagrams_received += 1
        lines = payload.splitlines() or [payload]
        for line in lines:
            self.stats.udp_lines_received += 1
            self._enqueue_bytes(line, "udp", peer)

    def stats_snapshot(self) -> dict[str, Any]:
        return {
            **asdict(self.stats),
            "queue_depth": self.queue.qsize(),
            "queue_capacity": self.config.queue_size,
            "udp_port": self.udp_port,
            "tcp_port": self.tcp_port,
            "bind_host": self.config.bind_host,
        }

    async def wait_for_persisted_batches(
        self,
        count: int,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while self.stats.persisted_batches < count:
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError(f"Collector did not persist {count} batch(es) in time.")
            await asyncio.sleep(0.01)

    async def _handle_tcp(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if self.stats.active_connections >= self.config.max_connections:
            self.stats.tcp_connections_rejected += 1
            writer.close()
            await writer.wait_closed()
            return

        self.stats.tcp_connections_accepted += 1
        self.stats.active_connections += 1
        self._writers.add(writer)
        peer = _peer_text(writer.get_extra_info("peername"))
        try:
            while not self._stopping.is_set():
                try:
                    payload = await asyncio.wait_for(
                        reader.readuntil(b"\n"),
                        timeout=self.config.idle_timeout_seconds,
                    )
                except TimeoutError:
                    self.stats.idle_timeouts += 1
                    break
                except asyncio.LimitOverrunError:
                    self.stats.dropped_oversize += 1
                    break
                except asyncio.IncompleteReadError as exc:
                    if exc.partial:
                        self.stats.tcp_lines_received += 1
                        self._enqueue_bytes(exc.partial, "tcp", peer)
                    break

                self.stats.tcp_lines_received += 1
                self._enqueue_bytes(payload, "tcp", peer)
        finally:
            self._writers.discard(writer)
            self.stats.active_connections -= 1
            writer.close()
            await writer.wait_closed()

    def _enqueue_bytes(
        self,
        payload: bytes,
        protocol: Literal["udp", "tcp"],
        peer: str,
    ) -> None:
        payload = payload.rstrip(b"\r\n")
        if len(payload) > self.config.max_line_bytes:
            self.stats.dropped_oversize += 1
            return
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            self.stats.dropped_malformed += 1
            return
        if not text.strip() or "\x00" in text:
            self.stats.dropped_malformed += 1
            return

        envelope = SyslogEnvelope(
            protocol=protocol,
            text=text,
            peer=peer,
            received_at=datetime.now(UTC),
        )
        try:
            self.queue.put_nowait(envelope)
            self.stats.accepted_lines += 1
        except asyncio.QueueFull:
            self.stats.dropped_queue_full += 1

    async def _batch_worker(self) -> None:
        while True:
            if self._stopping.is_set() and self.queue.empty():
                return
            try:
                first = await asyncio.wait_for(
                    self.queue.get(),
                    timeout=min(0.1, self.config.flush_interval_seconds)
                    if self._stopping.is_set()
                    else self.config.flush_interval_seconds,
                )
            except TimeoutError:
                continue

            batch = [first]
            deadline = (
                asyncio.get_running_loop().time()
                + self.config.flush_interval_seconds
            )
            while len(batch) < self.config.batch_size:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    batch.append(
                        await asyncio.wait_for(
                            self.queue.get(), timeout=min(remaining, 0.1)
                        )
                    )
                except TimeoutError:
                    if self._stopping.is_set():
                        break

            self._batch_number += 1
            try:
                analysis_id = await asyncio.to_thread(
                    self._batch_sink,
                    batch,
                    self._batch_number,
                )
                self.stats.persisted_batches += 1
                self.stats.persisted_lines += len(batch)
                self.stats.last_analysis_id = analysis_id
                self.stats.last_error = None
            except Exception as exc:
                self.stats.failed_batches += 1
                self.stats.last_error = f"{type(exc).__name__}: {exc}"
            finally:
                for _ in batch:
                    self.queue.task_done()

    def _persist_batch(
        self,
        batch: list[SyslogEnvelope],
        batch_number: int,
    ) -> str | None:
        protocols = {item.protocol for item in batch}
        protocol = next(iter(protocols)) if len(protocols) == 1 else "mixed"
        filename = (
            f"syslog-{protocol}-{self._session_id}-{batch_number:06d}.log"
        )
        text = "\n".join(item.text for item in batch)
        result = analyze_text(
            text,
            filename,
            self.rules_root,
            rule_library=self._rule_library,
            correlation_patterns=self._correlation_patterns,
        )
        raw_lines = build_raw_lines_from_text(text, result.source_id)
        with SessionLocal() as session:
            persisted = persist_analysis(
                session,
                result,
                raw_lines,
                filename,
                source_type="syslog",
                evidence_origin="syslog",
            )
        return persisted.analysis_id


class _SyslogDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: SyslogCollector) -> None:
        self.collector = collector

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        self.collector.submit_udp_datagram(data, _peer_text(addr))

    def error_received(self, exc: Exception) -> None:
        self.collector.stats.transport_errors += 1
        self.collector.stats.last_error = f"{type(exc).__name__}: {exc}"


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _peer_text(peer: Any) -> str:
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return str(peer or "unknown")
