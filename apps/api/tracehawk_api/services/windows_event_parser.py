import json
from datetime import UTC, datetime
from typing import Any
from xml.etree import ElementTree

from tracehawk_api.models.domain import ParsedEvent
from tracehawk_api.services.json_log_parser import _flatten
from tracehawk_api.services.parsers import LogParser


class WindowsEventParser(LogParser):
    parser_name = "windows_event"
    supported_types = ["windows_event"]

    def can_parse(self, sample: str) -> bool:
        record = _loads_record(sample)
        return bool(record and _event_id(record) is not None and _provider_name(record))

    def parse_line(self, raw_line_id: str, source_id: str, raw_line: str) -> ParsedEvent | None:
        record = _loads_record(raw_line)
        if record is None:
            return None

        flattened = _flatten(record)
        event_id = _event_id(record)
        provider = _provider_name(record)
        event_data = _event_data(record)
        event_type = _event_type(event_id)
        username = _username(event_id, event_data)
        source_ip = _text(event_data.get("IpAddress") or event_data.get("SourceNetworkAddress"))
        computer = _first_text(
            flattened,
            [
                "MachineName",
                "Computer",
                "Event.System.Computer",
                "System.Computer",
                "ComputerName",
            ],
        )
        timestamp = _first_text(
            flattened,
            [
                "TimeCreated",
                "Event.System.TimeCreated.SystemTime",
                "System.TimeCreated.SystemTime",
                "SystemTime",
                "@timestamp",
            ],
        )
        channel = _first_text(flattened, ["Channel", "Event.System.Channel", "System.Channel"])
        message = _message(event_id, provider, username, source_ip, event_data)

        normalized = dict(flattened)
        normalized.update(event_data)
        normalized.update(
            {
                "event_id": event_id,
                "provider_name": provider,
                "channel": channel,
                "username": username,
                "source_ip": source_ip,
                "target_user": _text(event_data.get("TargetUserName")),
                "subject_user": _text(event_data.get("SubjectUserName")),
                "group_name": _text(event_data.get("TargetSid") or event_data.get("TargetUserName")),
                "ip_address": source_ip,
            }
        )

        return ParsedEvent(
            id=f"event:{raw_line_id}",
            source_id=source_id,
            raw_line_id=raw_line_id,
            event_time=_parse_time(timestamp),
            event_type=event_type,
            host=computer,
            service=provider,
            source_ip=source_ip,
            username=username,
            message=message,
            normalized_fields=normalized,
        )


def _loads_record(raw_line: str) -> dict[str, Any] | None:
    text = raw_line.strip()
    if not text:
        return None
    if text.startswith("<"):
        return _loads_xml_event(text)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _loads_xml_event(text: str) -> dict[str, Any] | None:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None
    if _local_name(root.tag) != "Event":
        return None

    system: dict[str, Any] = {}
    event_data: dict[str, Any] = {}
    for child in root:
        name = _local_name(child.tag)
        if name == "System":
            for item in child:
                item_name = _local_name(item.tag)
                if item_name == "Provider":
                    system["Provider"] = {"Name": item.attrib.get("Name")}
                elif item_name == "TimeCreated":
                    system["TimeCreated"] = {"SystemTime": item.attrib.get("SystemTime")}
                elif item_name == "EventID":
                    system["EventID"] = (item.text or "").strip()
                else:
                    system[item_name] = (item.text or "").strip()
        elif name in {"EventData", "UserData"}:
            for item in child.iter():
                if _local_name(item.tag) != "Data":
                    continue
                data_name = item.attrib.get("Name")
                if data_name:
                    event_data[data_name] = item.text or ""

    return {"Event": {"System": system, "EventData": event_data}}


def _event_id(record: dict[str, Any]) -> int | None:
    flattened = _flatten(record)
    value = _first_value(
        flattened,
        ["Id", "EventID", "Event.System.EventID", "System.EventID", "Event.System.EventID.#text"],
    )
    try:
        return int(str(value).strip()) if value is not None else None
    except ValueError:
        return None


def _provider_name(record: dict[str, Any]) -> str | None:
    flattened = _flatten(record)
    return _first_text(
        flattened,
        [
            "ProviderName",
            "Provider",
            "Event.System.Provider.Name",
            "System.Provider.Name",
            "Event.System.Provider.@Name",
        ],
    )


def _event_data(record: dict[str, Any]) -> dict[str, Any]:
    flattened = _flatten(record)
    data: dict[str, Any] = {}
    for prefix in ("Event.EventData.", "Event.UserData.", "EventData.", "UserData."):
        for key, value in flattened.items():
            if key.startswith(prefix):
                data[key.removeprefix(prefix)] = value

    properties = record.get("Properties")
    if isinstance(properties, dict):
        data.update(properties)

    event_data = (
        record.get("Event", {}).get("EventData")
        if isinstance(record.get("Event"), dict)
        else record.get("EventData")
    )
    if isinstance(event_data, dict):
        data.update(event_data)
        items = event_data.get("Data")
        if isinstance(items, list):
            data.update(_named_data_items(items))
    elif isinstance(event_data, list):
        data.update(_named_data_items(event_data))

    return data


def _named_data_items(items: list[Any]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("Name") or item.get("@Name") or item.get("name")
        value = item.get("#text", item.get("Value", item.get("value")))
        if name is not None:
            data[str(name)] = value
    return data


def _event_type(event_id: int | None) -> str:
    mapping = {
        4624: "windows_logon_success",
        4625: "windows_logon_failure",
        4720: "windows_account_created",
        4728: "windows_admin_group_member_added",
        4732: "windows_admin_group_member_added",
        1102: "windows_audit_log_cleared",
    }
    return mapping.get(event_id, f"windows_event_{event_id or 'unknown'}")


def _username(event_id: int | None, event_data: dict[str, Any]) -> str | None:
    if event_id in {4624, 4625}:
        return _text(event_data.get("TargetUserName"))
    return _text(event_data.get("SubjectUserName") or event_data.get("TargetUserName"))


def _message(
    event_id: int | None,
    provider: str | None,
    username: str | None,
    source_ip: str | None,
    event_data: dict[str, Any],
) -> str:
    action = {
        4624: "successful logon",
        4625: "failed logon",
        4720: "account created",
        4728: "global admin group member added",
        4732: "local admin group member added",
        1102: "audit log cleared",
    }.get(event_id, "windows event")
    parts = [provider or "windows", str(event_id or "unknown"), action]
    if username:
        parts.append(f"user={username}")
    if source_ip and source_ip not in {"-", "::1", "127.0.0.1"}:
        parts.append(f"source_ip={source_ip}")
    target = _text(event_data.get("MemberName") or event_data.get("TargetUserName"))
    if target and target != username:
        parts.append(f"target={target}")
    return " ".join(parts)


def _first_value(data: dict[str, Any], fields: list[str]) -> Any:
    for field in fields:
        value = data.get(field)
        if value is not None:
            return value
    return None


def _first_text(data: dict[str, Any], fields: list[str]) -> str | None:
    return _text(_first_value(data, fields))


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _local_name(tag: str) -> str:
    return tag.rsplit("}", maxsplit=1)[-1]
