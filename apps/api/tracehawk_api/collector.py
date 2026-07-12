from __future__ import annotations

import asyncio
import json
import signal
from pathlib import Path

from tracehawk_api.config import settings
from tracehawk_api.services.syslog_collector import (
    SyslogCollector,
    SyslogCollectorConfig,
)


async def serve() -> None:
    collector = SyslogCollector(
        SyslogCollectorConfig(
            bind_host=settings.syslog_bind_host,
            udp_port=settings.syslog_udp_port,
            tcp_port=settings.syslog_tcp_port,
            allow_remote_bind=settings.syslog_allow_remote_bind,
            max_line_bytes=settings.syslog_max_line_bytes,
            queue_size=settings.syslog_queue_size,
            max_connections=settings.syslog_max_connections,
            idle_timeout_seconds=settings.syslog_idle_timeout_seconds,
            batch_size=settings.syslog_batch_size,
            flush_interval_seconds=settings.syslog_flush_interval_seconds,
        ),
        _project_root() / "packages/rules",
    )
    await collector.start()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, stop_event.set)
        except NotImplementedError:
            pass

    print(json.dumps({"event": "syslog_collector_started", **collector.stats_snapshot()}))
    reporter = asyncio.create_task(_report_stats(collector, stop_event))
    try:
        await stop_event.wait()
    finally:
        reporter.cancel()
        await asyncio.gather(reporter, return_exceptions=True)
        await collector.stop()
        print(json.dumps({"event": "syslog_collector_stopped", **collector.stats_snapshot()}))


async def _report_stats(
    collector: SyslogCollector,
    stop_event: asyncio.Event,
) -> None:
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=settings.syslog_stats_interval_seconds,
            )
        except TimeoutError:
            print(json.dumps({"event": "syslog_collector_stats", **collector.stats_snapshot()}))


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
