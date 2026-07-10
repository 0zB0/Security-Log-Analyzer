import asyncio
import re
from pathlib import Path

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from tracehawk_api.auth import authenticate_headers, has_required_role, request_id_from_headers
from tracehawk_api.config import settings
from tracehawk_api.database import SessionLocal, init_db
from tracehawk_api.services.audit import record_audit_event
from tracehawk_api.services.live import (
    LiveDockerLogStreamer,
    LiveFileTailer,
    LiveFolderWatcher,
    LiveInterfacePacketStreamer,
    LiveTailControl,
)


router = APIRouter(prefix="/api/live", tags=["live"])


@router.websocket("/file")
async def live_file(websocket: WebSocket) -> None:
    if not await _authorize_live(websocket):
        return
    path_value = websocket.query_params.get("path")
    if not path_value:
        await websocket.close(code=1008, reason="Missing path query parameter.")
        return

    path = Path(path_value).expanduser()
    if not path.exists() or not path.is_file():
        await websocket.close(code=1008, reason="Path must be an existing file.")
        return

    start_at_end = websocket.query_params.get("start_at_end", "true").lower() != "false"
    await websocket.accept()

    tailer = LiveFileTailer(
        path=path,
        rules_root=_project_root() / "packages/rules",
        start_at_end=start_at_end,
    )
    control = LiveTailControl()
    send_lock = asyncio.Lock()

    async def send_snapshot(status: str | None = None) -> None:
        snapshot_status = status or ("paused" if control.paused else "active")
        async with send_lock:
            await websocket.send_json(tailer.snapshot(status=snapshot_status).model_dump(mode="json"))

    async def produce_snapshots() -> None:
        async for snapshot in tailer.snapshots(control):
            async with send_lock:
                await websocket.send_json(snapshot.model_dump(mode="json"))

    async def receive_commands() -> None:
        while True:
            message = await websocket.receive_json()
            action = str(message.get("action", "")).lower()
            if action == "pause":
                control.paused = True
                await send_snapshot("paused")
            elif action == "resume":
                control.paused = False
                await send_snapshot("active")
            elif action == "ping":
                await send_snapshot()

    producer = asyncio.create_task(produce_snapshots())
    consumer = asyncio.create_task(receive_commands())
    try:
        done, pending = await asyncio.wait(
            {producer, consumer},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        for task in done:
            task.result()
    except WebSocketDisconnect:
        return
    finally:
        producer.cancel()
        consumer.cancel()


@router.websocket("/folder")
async def live_folder(websocket: WebSocket) -> None:
    if not await _authorize_live(websocket):
        return
    path_value = websocket.query_params.get("path")
    if not path_value:
        await websocket.close(code=1008, reason="Missing path query parameter.")
        return

    path = Path(path_value).expanduser()
    if not path.exists() or not path.is_dir():
        await websocket.close(code=1008, reason="Path must be an existing folder.")
        return

    pattern = websocket.query_params.get("pattern", "*.log")
    start_at_end = websocket.query_params.get("start_at_end", "true").lower() != "false"
    watcher = LiveFolderWatcher(
        path=path,
        rules_root=_project_root() / "packages/rules",
        pattern=pattern,
        start_at_end=start_at_end,
    )
    await _stream_live_snapshots(websocket, watcher)


@router.websocket("/docker")
async def live_docker(websocket: WebSocket) -> None:
    if not await _authorize_live(websocket):
        return
    container = websocket.query_params.get("container")
    if not container:
        await websocket.close(code=1008, reason="Missing container query parameter.")
        return

    tail = websocket.query_params.get("tail", "0")
    streamer = LiveDockerLogStreamer(
        container=container,
        rules_root=_project_root() / "packages/rules",
        tail=tail,
    )
    await _stream_live_snapshots(websocket, streamer)


@router.websocket("/interface")
async def live_interface(websocket: WebSocket) -> None:
    if not await _authorize_live(websocket):
        return
    interface = websocket.query_params.get("interface")
    if not interface:
        await websocket.close(code=1008, reason="Missing interface query parameter.")
        return
    if not _valid_interface(interface):
        await websocket.close(code=1008, reason="Interface name contains unsupported characters.")
        return

    capture_filter = websocket.query_params.get("capture_filter", "ip or ip6")
    if len(capture_filter) > 300:
        await websocket.close(code=1008, reason="Capture filter is too long.")
        return

    streamer = LiveInterfacePacketStreamer(
        interface=interface,
        rules_root=_project_root() / "packages/rules",
        capture_filter=capture_filter,
    )
    await _stream_live_snapshots(websocket, streamer)


async def _stream_live_snapshots(websocket: WebSocket, source) -> None:
    await websocket.accept()
    control = LiveTailControl()
    send_lock = asyncio.Lock()

    async def send_snapshot(status: str | None = None) -> None:
        snapshot_status = status or ("paused" if control.paused else "active")
        async with send_lock:
            await websocket.send_json(source.snapshot(status=snapshot_status).model_dump(mode="json"))

    async def produce_snapshots() -> None:
        async for snapshot in source.snapshots(control):
            async with send_lock:
                await websocket.send_json(snapshot.model_dump(mode="json"))

    async def receive_commands() -> None:
        while True:
            message = await websocket.receive_json()
            action = str(message.get("action", "")).lower()
            if action == "pause":
                control.paused = True
                await send_snapshot("paused")
            elif action == "resume":
                control.paused = False
                await send_snapshot("active")
            elif action == "ping":
                await send_snapshot()

    producer = asyncio.create_task(produce_snapshots())
    consumer = asyncio.create_task(receive_commands())
    try:
        done, pending = await asyncio.wait(
            {producer, consumer},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        for task in done:
            task.result()
    except WebSocketDisconnect:
        return
    finally:
        producer.cancel()
        consumer.cancel()


def _project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _valid_interface(interface: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", interface))


async def _authorize_live(websocket: WebSocket) -> bool:
    authentication = authenticate_headers(websocket.headers)
    principal = authentication.principal
    request_id = request_id_from_headers(websocket.headers)
    if authentication.error == "missing":
        _audit_websocket(websocket, None, 401, request_id)
        await websocket.close(code=4401, reason="Authentication required.")
        return False
    if authentication.error == "not_allowed":
        _audit_websocket(
            websocket,
            None,
            403,
            request_id,
            attempted_email=authentication.email,
        )
        await websocket.close(code=4403, reason="Account is not allowed.")
        return False
    assert principal is not None
    if not has_required_role(principal, "analyst"):
        _audit_websocket(websocket, principal, 403, request_id)
        await websocket.close(code=4403, reason="The analyst role is required.")
        return False
    websocket.state.principal = principal
    websocket.state.request_id = request_id
    _audit_websocket(websocket, principal, 101, request_id)
    return True


def _audit_websocket(
    websocket: WebSocket,
    principal,
    status_code: int,
    request_id: str,
    *,
    attempted_email: str | None = None,
) -> None:
    init_db()
    with SessionLocal() as session:
        record_audit_event(
            session,
            principal=principal,
            method="WEBSOCKET",
            path=websocket.url.path,
            status_code=status_code,
            request_id=request_id,
            attempted_email=attempted_email,
            auth_mode=settings.auth_mode,
        )
