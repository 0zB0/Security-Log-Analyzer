from tracehawk_api.services.csv_log_parser import CsvLogParser
from tracehawk_api.services.cloudtrail_parser import CloudTrailParser
from tracehawk_api.services.json_log_parser import JsonLogParser
from tracehawk_api.services.kubernetes_audit_parser import KubernetesAuditParser
from tracehawk_api.services.linux_auth_parser import LinuxAuthParser
from tracehawk_api.services.parsers import LogParser
from tracehawk_api.services.suricata_eve_parser import SuricataEveParser
from tracehawk_api.services.syslog_parser import GenericSyslogParser
from tracehawk_api.services.web_access_parser import WebAccessParser
from tracehawk_api.services.windows_event_parser import WindowsEventParser
from tracehawk_api.services.zeek_json_parser import ZeekJsonParser
from tracehawk_api.services.zeek_tsv_parser import ZeekTsvParser


def default_parsers() -> list[LogParser]:
    return [
        SuricataEveParser(),
        ZeekJsonParser(),
        ZeekTsvParser(),
        CloudTrailParser(),
        KubernetesAuditParser(),
        WindowsEventParser(),
        LinuxAuthParser(),
        WebAccessParser(),
        CsvLogParser(),
        JsonLogParser(),
        GenericSyslogParser(),
    ]
