from tracehawk_api.services.windows_event_parser import WindowsEventParser


def test_windows_event_parser_reads_one_line_event_xml() -> None:
    raw = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        '<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        "<EventID>4625</EventID>"
        '<TimeCreated SystemTime="2026-07-09T11:00:00Z"/>'
        "<Computer>WIN-DC01</Computer>"
        "<Channel>Security</Channel>"
        "</System>"
        "<EventData>"
        '<Data Name="TargetUserName">bob</Data>'
        '<Data Name="IpAddress">198.51.100.77</Data>'
        "</EventData>"
        "</Event>"
    )

    parser = WindowsEventParser()
    event = parser.parse_line("line:1", "source:1", raw)

    assert parser.can_parse(raw)
    assert event is not None
    assert event.event_type == "windows_logon_failure"
    assert event.username == "bob"
    assert event.source_ip == "198.51.100.77"
    assert event.host == "WIN-DC01"
    assert event.normalized_fields["event_id"] == 4625
