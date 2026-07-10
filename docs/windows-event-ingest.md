# Windows Event Ingest

TraceHawk accepts exported Windows Security events as UTF-8 text. This slice supports JSON Lines and one-line Windows Event XML records. Native binary `.evtx` parsing is not included; export first with PowerShell, Windows Event Viewer, or another local tool.

## Parser

The `windows_event` parser recognizes records with a Windows event ID and provider name.

Supported shapes:

- flat JSON Lines from common `Get-WinEvent` exports, with fields such as `ProviderName`, `Id`, `TimeCreated`, `MachineName`, and `Properties`;
- nested JSON records with `Event.System` and `Event.EventData`;
- one-line XML `<Event>` records with `System` and `EventData/Data` fields.

Normalized event behavior:

- `event_id` is the integer Windows event ID;
- `event_type` maps key Security events such as 4624, 4625, 4720, 4728, 4732, and 1102;
- `username` comes from `TargetUserName` for logon events and `SubjectUserName` for administrative events;
- `source_ip` comes from `IpAddress` or `SourceNetworkAddress`;
- event data fields remain available for rule matching.

## Detection Pack

The Windows rules cover:

- failed logon burst;
- successful logon after repeated failures;
- user account creation;
- privileged group membership changes;
- Security audit log clearing.

## Local Sample

```bash
curl -F "file=@packages/sample-data/windows/security-risk.jsonl" \
  http://localhost:8000/api/analyze/upload
```

The same sample is available in the UI sample selector as `Windows Security risk`.
