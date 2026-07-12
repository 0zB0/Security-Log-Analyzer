import asyncio
from pathlib import Path
from typing import Any

import pytest

from tracehawk_api.database import SessionLocal
from tracehawk_api.services.persistence import get_analysis_result, list_analysis_runs
from tracehawk_api.services.syslog_collector import (
    SyslogCollector,
    SyslogCollectorConfig,
    SyslogEnvelope,
)


ROOT = Path(__file__).resolve().parents[3]
RULES = ROOT / "packages/rules"
SYSLOG_LINES = (
    ROOT / "packages/test-scenarios/syslog-error-burst/input.log"
).read_text().splitlines()


def test_remote_bind_is_refused_without_explicit_override() -> None:
    with pytest.raises(ValueError, match="Remote syslog bind refused"):
        SyslogCollectorConfig(bind_host="0.0.0.0")

    config = SyslogCollectorConfig(
        bind_host="0.0.0.0",
        allow_remote_bind=True,
    )

    assert config.bind_host == "0.0.0.0"


def test_queue_line_and_encoding_limits_increment_drop_counters() -> None:
    collector = SyslogCollector(
        SyslogCollectorConfig(
            enable_tcp=False,
            queue_size=1,
            max_line_bytes=128,
        ),
        RULES,
        batch_sink=lambda _batch, _number: None,
    )

    collector.submit_udp_datagram(SYSLOG_LINES[0].encode())
    collector.submit_udp_datagram(SYSLOG_LINES[1].encode())
    collector.submit_udp_datagram(b"x" * 129)
    collector.submit_udp_datagram(b"\xff\xfe")
    collector.submit_udp_datagram(b"\n")

    assert collector.stats.accepted_lines == 1
    assert collector.stats.dropped_queue_full == 1
    assert collector.stats.dropped_oversize == 1
    assert collector.stats.dropped_malformed == 2
    assert collector.queue.qsize() == 1


def test_udp_and_tcp_batches_use_analysis_integrity_and_persistence() -> None:
    asyncio.run(_udp_and_tcp_pipeline_scenario())


async def _udp_and_tcp_pipeline_scenario() -> None:
    collector = SyslogCollector(
        SyslogCollectorConfig(
            udp_port=0,
            tcp_port=0,
            batch_size=5,
            flush_interval_seconds=0.05,
            idle_timeout_seconds=1,
        ),
        RULES,
    )
    await collector.start()
    try:
        assert collector.udp_port is not None
        assert collector.tcp_port is not None
        await _send_udp(collector.udp_port, SYSLOG_LINES)
        await collector.wait_for_persisted_batches(1)

        reader, writer = await asyncio.open_connection("127.0.0.1", collector.tcp_port)
        del reader
        writer.write(("\n".join(SYSLOG_LINES) + "\n").encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await collector.wait_for_persisted_batches(2)
    finally:
        await collector.stop()

    assert collector.stats.udp_datagrams_received == 5
    assert collector.stats.tcp_connections_accepted == 1
    assert collector.stats.accepted_lines == 10
    assert collector.stats.persisted_lines == 10
    assert collector.stats.failed_batches == 0
    assert collector.stats.active_connections == 0

    with SessionLocal() as session:
        runs = list_analysis_runs(session)
        assert len(runs) == 2
        restored = [
            get_analysis_result(session, run.id)
            for run in runs
        ]

    assert all(result is not None for result in restored)
    assert all(result.parser == "syslog" for result in restored if result is not None)
    assert all(result.finding_count == 1 for result in restored if result is not None)
    assert all(
        result.evidence_integrity is not None
        and result.evidence_integrity.origin == "syslog"
        and result.evidence_integrity.status == "verified"
        for result in restored
        if result is not None
    )


def test_failed_batch_recovers_and_graceful_stop_drains_queue() -> None:
    asyncio.run(_failure_recovery_scenario())


async def _failure_recovery_scenario() -> None:
    persisted: list[list[SyslogEnvelope]] = []

    def sink(batch: list[SyslogEnvelope], batch_number: int) -> str:
        if batch_number == 1:
            raise ValueError("synthetic batch rejection")
        persisted.append(batch)
        return f"analysis:test:{batch_number}"

    collector = SyslogCollector(
        SyslogCollectorConfig(
            enable_tcp=False,
            udp_port=0,
            batch_size=1,
            flush_interval_seconds=30,
        ),
        RULES,
        batch_sink=sink,
    )
    await collector.start()
    collector.submit_udp_datagram(SYSLOG_LINES[0].encode())
    await _wait_until(lambda: collector.stats.failed_batches == 1)
    collector.submit_udp_datagram(SYSLOG_LINES[1].encode())
    await collector.wait_for_persisted_batches(1)
    collector.submit_udp_datagram(SYSLOG_LINES[2].encode())
    await collector.stop()

    assert collector.stats.failed_batches == 1
    assert collector.stats.persisted_batches == 2
    assert collector.stats.persisted_lines == 2
    assert [batch[0].text for batch in persisted] == SYSLOG_LINES[1:3]
    assert "synthetic batch rejection" not in (collector.stats.last_error or "")


def test_tcp_connection_limit_and_idle_timeout_are_enforced() -> None:
    asyncio.run(_tcp_connection_boundary_scenario())


async def _tcp_connection_boundary_scenario() -> None:
    collector = SyslogCollector(
        SyslogCollectorConfig(
            enable_udp=False,
            tcp_port=0,
            max_connections=1,
            idle_timeout_seconds=0.05,
            flush_interval_seconds=0.05,
        ),
        RULES,
        batch_sink=lambda _batch, _number: None,
    )
    await collector.start()
    try:
        assert collector.tcp_port is not None
        first_reader, first_writer = await asyncio.open_connection(
            "127.0.0.1", collector.tcp_port
        )
        await _wait_until(lambda: collector.stats.active_connections == 1)
        second_reader, second_writer = await asyncio.open_connection(
            "127.0.0.1", collector.tcp_port
        )
        await _wait_until(lambda: collector.stats.tcp_connections_rejected == 1)
        assert await second_reader.read() == b""
        second_writer.close()
        await second_writer.wait_closed()

        await _wait_until(lambda: collector.stats.idle_timeouts == 1)
        assert await first_reader.read() == b""
        first_writer.close()
        await first_writer.wait_closed()
    finally:
        await collector.stop()

    assert collector.stats.tcp_connections_accepted == 1
    assert collector.stats.tcp_connections_rejected == 1
    assert collector.stats.active_connections == 0


async def _send_udp(port: int, lines: list[str]) -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol,
        remote_addr=("127.0.0.1", port),
    )
    try:
        for line in lines:
            transport.sendto(line.encode())
        await asyncio.sleep(0.05)
    finally:
        transport.close()


async def _wait_until(predicate: Any, timeout_seconds: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while not predicate():
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError("Collector condition was not reached in time.")
        await asyncio.sleep(0.01)
