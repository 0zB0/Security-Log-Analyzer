# CloudTrail Ingest

TraceHawk supports AWS CloudTrail JSON Lines exports as a local-only ingest path.

The parser recognizes records with `eventSource`, `eventName`, and `eventTime`, then normalizes:

- `eventName` as the event type;
- `eventSource` as the service;
- `sourceIPAddress` as source IP;
- `userIdentity.userName`, `userIdentity.arn`, or `userIdentity.principalId` as username;
- `awsRegion` as host context.

Initial deterministic rules cover:

- failed AWS ConsoleLogin bursts;
- root account usage;
- access key creation;
- IAM policy attachment or inline policy changes;
- CloudTrail logging disable/delete/update events.

Sample:

```bash
curl -F "file=@packages/sample-data/cloudtrail/iam-risk.jsonl" \
  http://localhost:8000/api/analyze/upload
```

Scenario contract:

```bash
.venv/bin/python -m pytest apps/api/tests/test_scenarios.py -q
```
