import type { WorkspaceView } from "../../app/workspaceTypes";

export type PublicTutorialView = Extract<
  WorkspaceView,
  | "upload"
  | "incidents"
  | "findings"
  | "evidence"
  | "entities"
  | "mitre"
  | "reports"
  | "library"
>;

export interface TutorialStep {
  target: string;
  title: string;
  body: string;
}

export interface TutorialDisplayItem {
  label: string;
  explanation: string;
  example: string;
}

export interface TutorialControl {
  label: string;
  kind: "button" | "field" | "selector" | "toggle";
  action: string;
  result: string;
}

export interface TutorialExample {
  scenario: string;
  observation: string;
  interpretation: string;
  nextStep: string;
}

export interface TutorialSection {
  view: PublicTutorialView;
  title: string;
  purpose: string;
  dataOrigin: string;
  readingMethod: string;
  limitation: string;
  whatItShows: TutorialDisplayItem[];
  example: TutorialExample;
  controls: TutorialControl[];
  steps: TutorialStep[];
}

export const COMMON_TUTORIAL_CONTROLS: TutorialControl[] = [
  {
    label: "Upload",
    kind: "button",
    action: "Opens the upload and investigation overview.",
    result: "The current in-memory analysis stays loaded; only the visible view changes.",
  },
  {
    label: "Entities",
    kind: "button",
    action: "Opens the inventory of extracted IPs, users, hosts, services, paths, domains, and containers.",
    result: "You can pivot from an entity to its linked incident or finding.",
  },
  {
    label: "MITRE",
    kind: "button",
    action: "Opens the ATT&CK tactic and technique grouping for the current findings.",
    result: "No new detection runs; the existing findings are reorganized as ATT&CK context.",
  },
  {
    label: "Incidents",
    kind: "button",
    action: "Opens correlated investigation stories.",
    result: "The strongest incident is selected unless you already selected another one.",
  },
  {
    label: "Findings",
    kind: "button",
    action: "Opens individual deterministic rule matches.",
    result: "The selected finding and its supporting evidence are shown together.",
  },
  {
    label: "Evidence",
    kind: "button",
    action: "Opens the line-level evidence review.",
    result: "Raw lines, hashes, rule metadata, severity, confidence, and MITRE context become visible.",
  },
  {
    label: "Reports",
    kind: "button",
    action: "Opens the session-only Markdown report builder.",
    result: "Nothing is generated or downloaded until you explicitly use the report controls.",
  },
  {
    label: "Library",
    kind: "button",
    action: "Opens the transparent detection-rule library.",
    result: "You can inspect what every rule looks for, its false positives, and its next steps.",
  },
  {
    label: "Tutorial",
    kind: "button",
    action: "Opens this learning tool.",
    result: "The current analysis remains in memory while you read or start a guided tour.",
  },
  {
    label: "Global investigation search",
    kind: "field",
    action: "Filters finding-based panels by title, rule, summary, reason, severity, confidence, or MITRE value.",
    result: "It narrows the current result locally and never re-runs or changes the uploaded analysis.",
  },
  {
    label: "Clear session — top bar",
    kind: "button",
    action: "Clears the current analysis, selections, report, search, errors, and inactivity timer.",
    result: "The workspace returns to an empty state. This cannot be undone.",
  },
  {
    label: "Clear session — privacy banner",
    kind: "button",
    action: "Performs the same complete in-browser clear from the session status area.",
    result: "All visitor evidence and derived results disappear from React memory.",
  },
  {
    label: "Browse…",
    kind: "button",
    action: "Opens the browser file picker for one supported text log.",
    result: "After selection, the browser reads the file and sends it once to the stateless analysis endpoint.",
  },
  {
    label: "Run demo",
    kind: "button",
    action: "Runs the fixed sanitized SSH-compromise demonstration.",
    result: "A real deterministic analysis is loaded and the workspace moves to Incidents.",
  },
  {
    label: "Sample scenario",
    kind: "selector",
    action: "Chooses Auth SSH compromise, Suricata alert burst, or Zeek port scan.",
    result: "Selection alone does nothing; Run sample executes the chosen scenario.",
  },
  {
    label: "Run sample",
    kind: "button",
    action: "Analyzes the scenario currently selected in Sample scenario.",
    result: "The new session result replaces any previous result and opens Incidents.",
  },
  {
    label: "Markdown — intake shortcut",
    kind: "button",
    action: "Switches the report format to Markdown and opens Reports.",
    result: "It does not generate a report; Generate report remains a separate explicit action.",
  },
  {
    label: "Question-mark help",
    kind: "button",
    action: "Starts the guided tour for the currently open view.",
    result: "The tour highlights real interface targets and explains them step by step without changing evidence.",
  },
];

export const TUTORIAL_SECTIONS: TutorialSection[] = [
  {
    view: "upload",
    title: "Upload",
    purpose: "Start an investigation and verify what the parser and detection engine produced before drawing conclusions.",
    dataOrigin: "The selected file is read by this browser and sent once to the stateless demo endpoint. Samples are sanitized files shipped with TraceHawk.",
    readingMethod: "Read intake status first, then compare parser, raw lines, events, findings, incidents, and the evidence preview.",
    limitation: "Compressed, binary, oversized, and unsupported files are rejected. Refresh clears the result.",
    whatItShows: [
      {
        label: "Investigation intake",
        explanation: "Shows whether a file or sample is loaded, which parser handled it, and how many findings were produced.",
        example: "linux_auth / 4 findings means the Linux authentication parser normalized the source and four rules matched.",
      },
      {
        label: "Metric cards",
        explanation: "Separate source volume from analytical output: parser, raw lines, parsed events, findings, and incidents.",
        example: "12 raw lines and 12 events means every line parsed; four findings grouped into one incident means several signals describe one story.",
      },
      {
        label: "Investigation preview",
        explanation: "Shows incidents, individual findings, and exact evidence together so a result can be challenged immediately.",
        example: "A critical incident can contain a high-severity brute-force finding plus later successful login and privileged activity findings.",
      },
    ],
    example: {
      scenario: "Run the Auth SSH compromise sample.",
      observation: "TraceHawk shows 12 lines, 12 events, four findings, and one incident with a score of 100.",
      interpretation: "Repeated failures, a successful login, and a privileged account-management command occurred in a meaningful sequence. The score prioritizes review; it is not proof by itself.",
      nextStep: "Open Incidents for the sequence, then Findings and Evidence to validate every rule against raw lines.",
    },
    controls: [
      {
        label: "Incident card",
        kind: "button",
        action: "Selects one correlated incident from the overview.",
        result: "The card becomes selected and its related investigation context is used by other views.",
      },
      {
        label: "Finding card",
        kind: "button",
        action: "Selects an individual rule match.",
        result: "The Evidence panel updates to the exact raw lines behind that finding.",
      },
      {
        label: "Rule",
        kind: "button",
        action: "Opens the selected finding's rule in Library.",
        result: "You see rule intent, matching logic, correlation behavior, false positives, and analyst next steps.",
      },
    ],
    steps: [
      { target: '[data-tour="nav-upload"]', title: "Upload workspace", body: "Start every public investigation here. Changing views never duplicates or persists the current result." },
      { target: '[data-tour="upload-intake"]', title: "Investigation intake", body: "This strip contains Browse, Run demo, Sample scenario, Run sample, and the Markdown shortcut." },
      { target: '[data-tour="upload-file"]', title: "Browse for your log", body: "Browse opens one local text file. Selecting it immediately starts bounded stateless analysis." },
      { target: '[data-tour="upload-demo"]', title: "Run the fixed demo", body: "Run demo always loads the sanitized SSH compromise so every learner starts from the same evidence." },
      { target: '[data-tour="upload-samples"]', title: "Choose and run a sample", body: "The selector chooses a scenario; Run sample executes it and replaces the previous in-memory result." },
      { target: '[data-tour="upload-markdown"]', title: "Open the report builder", body: "Markdown opens Reports and selects Markdown. It does not generate or download anything yet." },
      { target: '[data-tour="view-upload-content"]', title: "Read the investigation preview", body: "Incident cards select stories, finding cards select detections, and Rule opens transparent detection logic." },
      { target: '[data-tour="session-privacy"]', title: "Privacy boundary", body: "The server does not persist uploaded evidence. Clear session, refresh, tab close, or inactivity removes the browser result." },
    ],
  },
  {
    view: "incidents",
    title: "Incidents",
    purpose: "Prioritize correlated security stories instead of reviewing isolated alerts without sequence or entity context.",
    dataOrigin: "Incidents are derived from deterministic findings, shared entities, time proximity, declared sequences, and correlation patterns.",
    readingMethod: "Start with severity and score, then verify scoring rationale, linked findings, entities, time window, and timeline order.",
    limitation: "A correlation score prioritizes review; it does not prove compromise.",
    whatItShows: [
      {
        label: "Incident list",
        explanation: "Ranks grouped stories with severity, score, finding count, timeline count, MITRE techniques, and entities.",
        example: "Possible SSH credential compromise links user:admin and ip:198.51.100.10 across four findings.",
      },
      {
        label: "Scoring rationale",
        explanation: "Explains every score component instead of presenting an unexplained risk number.",
        example: "Sequence quality contributes when failures are followed by success and privileged activity in order.",
      },
      {
        label: "Linked findings and timeline",
        explanation: "Connects the story back to individual detections and chronological raw-event summaries.",
        example: "Ten failures precede one accepted login and then a sudo useradd command.",
      },
    ],
    example: {
      scenario: "Inspect the score-100 SSH incident.",
      observation: "Critical severity, four linked findings, three ATT&CK techniques, and a twelve-event timeline are shown.",
      interpretation: "The ordered evidence is stronger than four unrelated alerts, but an analyst must still validate account ownership and expected administration activity.",
      nextStep: "Open each linked finding, compare its evidence, then inspect the entities shared across the sequence.",
    },
    controls: [
      {
        label: "Incident card",
        kind: "button",
        action: "Selects that incident.",
        result: "The detail panel changes to its score, rationale, entities, linked findings, notes state, and timeline.",
      },
      {
        label: "Linked finding",
        kind: "button",
        action: "Selects one finding belonging to the incident.",
        result: "The selection is preserved for Findings and Evidence review.",
      },
      {
        label: "Save note",
        kind: "button",
        action: "Would persist an analyst note in the private workspace.",
        result: "It is disabled in the public demo because session-only mode forbids persistence.",
      },
    ],
    steps: [
      { target: '[data-tour="nav-incidents"]', title: "Incident desk", body: "Open grouped security stories after analysis." },
      { target: '[data-tour="incident-list"]', title: "Choose an incident", body: "Clicking an incident card selects the story and updates the detail panel." },
      { target: '[data-tour="incident-detail"]', title: "Read score and context", body: "Compare score, rationale, entities, MITRE techniques, and time window before accepting priority." },
      { target: '[data-tour="incident-linked-findings"]', title: "Open linked findings", body: "Each linked-finding button selects the detection so you can validate it in Findings or Evidence." },
      { target: '[data-tour="incident-timeline"]', title: "Verify chronology", body: "Read the ordered failures, success, and privileged action. Sequence is the core learning signal here." },
    ],
  },
  {
    view: "findings",
    title: "Findings",
    purpose: "Inspect individual deterministic detections before treating a correlated incident as valid.",
    dataOrigin: "Each finding is produced by a versioned YAML rule applied to normalized log events.",
    readingMethod: "Compare title, severity, confidence, event count, MITRE mapping, rule explanation, and exact evidence.",
    limitation: "A finding is a heuristic signal and may be a false positive.",
    whatItShows: [
      {
        label: "Finding list",
        explanation: "Shows every matched rule with severity, confidence, event count, and MITRE technique.",
        example: "SSH brute force attempt can be high severity, high confidence, ten events, and T1110.001.",
      },
      {
        label: "Evidence preview",
        explanation: "Shows why the currently selected finding matched without leaving the page.",
        example: "Ten numbered Failed password lines support the brute-force threshold match.",
      },
    ],
    example: {
      scenario: "Select SSH successful login after repeated failures.",
      observation: "The finding reports a critical two-step sequence across eleven events and maps to T1078.",
      interpretation: "A success after repeated failures is higher priority than either event type alone, but could still be a legitimate user mistyping a password.",
      nextStep: "Open Rule to review thresholds and false positives, then verify source IP, username, and timestamps in Evidence.",
    },
    controls: [
      {
        label: "Finding card",
        kind: "button",
        action: "Selects the finding.",
        result: "The evidence preview changes to that finding's reason, metadata, and raw lines.",
      },
      {
        label: "Rule",
        kind: "button",
        action: "Opens the matching rule in Library.",
        result: "You can inspect logic, false positives, correlation behavior, and recommended next steps.",
      },
    ],
    steps: [
      { target: '[data-tour="nav-findings"]', title: "Finding review", body: "Move from incident-level priority to individual deterministic detections." },
      { target: '[data-tour="finding-list"]', title: "Select a finding", body: "A finding card updates the evidence preview; Rule opens the exact detection definition in Library." },
      { target: '[data-tour="finding-evidence"]', title: "Challenge the match", body: "Compare the rule reason, severity, confidence, event count, and raw lines before accepting the signal." },
    ],
  },
  {
    view: "evidence",
    title: "Evidence",
    purpose: "Inspect exact source lines and integrity metadata behind a selected finding.",
    dataOrigin: "Evidence lines come from the current browser-session upload and include a SHA-256 content hash.",
    readingMethod: "Compare the raw line, line number, parser output, rule, severity, confidence, MITRE mapping, and hash.",
    limitation: "The hash proves content consistency inside this analysis, not external chain of custody.",
    whatItShows: [
      {
        label: "Finding selector",
        explanation: "Keeps detection context next to the raw evidence it references.",
        example: "Selecting the brute-force finding limits the raw viewer to its ten failed-login lines.",
      },
      {
        label: "Raw evidence",
        explanation: "Shows numbered source lines without replacing them with an AI summary.",
        example: "Line 1 can show Failed password for admin from 198.51.100.10 with the original port and message.",
      },
      {
        label: "Evidence metadata",
        explanation: "Shows rule, severity, confidence, event count, evidence count, MITRE technique, and truncated content hashes.",
        example: "Ten unique hashes show ten captured lines were individually fingerprinted.",
      },
    ],
    example: {
      scenario: "Review the ten failed SSH login lines.",
      observation: "The same username and source IP repeat across increasing line numbers and ports.",
      interpretation: "The repetition supports password guessing, while ports changing is normal client behavior and not a separate attacker identity.",
      nextStep: "Check whether the later success uses the same IP and user, then compare the rule's false-positive guidance.",
    },
    controls: [
      {
        label: "Finding card",
        kind: "button",
        action: "Selects which finding owns the evidence context.",
        result: "Raw evidence and metadata update to only the selected finding.",
      },
      {
        label: "Rule",
        kind: "button",
        action: "Opens the selected finding's rule definition.",
        result: "The learning flow moves from observed evidence to rule logic and expected false positives.",
      },
    ],
    steps: [
      { target: '[data-tour="nav-evidence"]', title: "Evidence review", body: "Use raw data to challenge the selected detection." },
      { target: '[data-tour="evidence-findings"]', title: "Choose the evidence context", body: "Finding cards switch the raw lines and metadata; Rule opens the transparent rule definition." },
      { target: '[data-tour="evidence-raw"]', title: "Read exact lines", body: "Line numbers and untouched text show what the parser and rule actually received." },
      { target: '[data-tour="evidence-metadata"]', title: "Verify metadata and hashes", body: "Compare rule, severity, confidence, count, MITRE mapping, and per-line content fingerprints." },
    ],
  },
  {
    view: "entities",
    title: "Entities",
    purpose: "Pivot across people, systems, addresses, services, paths, domains, and containers shared by detections.",
    dataOrigin: "Entities are extracted from normalized events and linked back to findings and incidents.",
    readingMethod: "Prioritize high-risk, high-frequency entities and then follow their incident and finding links.",
    limitation: "Entity extraction is parser-dependent and does not resolve external ownership or reputation.",
    whatItShows: [
      {
        label: "Entity identity",
        explanation: "Shows entity type and normalized value, such as IP, user, host, service, path, domain, or container.",
        example: "ip / 198.51.100.10 identifies one source address extracted from authentication events.",
      },
      {
        label: "Risk and activity",
        explanation: "Shows risk score, event count, finding count, and incident count for prioritization.",
        example: "An IP linked to ten events, three findings, and one critical incident deserves review before a one-off host value.",
      },
      {
        label: "Pivot links",
        explanation: "Provides direct buttons back to related incidents and findings.",
        example: "Clicking Possible SSH credential compromise selects that incident; clicking a short finding ID selects the detection.",
      },
    ],
    example: {
      scenario: "Inspect ip:198.51.100.10 and user:admin.",
      observation: "Both appear across failed logins, the accepted login, and the correlated incident.",
      interpretation: "Shared entities explain why events were grouped, but the IP is documentation space and does not provide real reputation data.",
      nextStep: "Open the incident link for sequence context, then the finding link for rule and evidence validation.",
    },
    controls: [
      {
        label: "Incident title chip",
        kind: "button",
        action: "Selects the incident linked to this entity.",
        result: "The incident is preserved as the active story for the Incidents and Reports views.",
      },
      {
        label: "Finding ID chip",
        kind: "button",
        action: "Selects the linked finding.",
        result: "The active finding changes for Findings and Evidence review.",
      },
    ],
    steps: [
      { target: '[data-tour="nav-entities"]', title: "Entity inventory", body: "Open the people, systems, and addresses extracted from current evidence." },
      { target: '[data-tour="entity-cards"]', title: "Read identity and risk", body: "Compare entity type, value, risk, event volume, finding count, and incident count." },
      { target: '[data-tour="entity-links"]', title: "Use pivot buttons", body: "Incident-title buttons select a story; short-ID buttons select a finding. Neither re-runs analysis." },
    ],
  },
  {
    view: "mitre",
    title: "MITRE",
    purpose: "Translate current detections into ATT&CK tactics and techniques without treating classification as proof.",
    dataOrigin: "Mappings are declared by detection rules and shown only for findings in this analysis.",
    readingMethod: "Read tactic, technique ID and name, maximum severity, rule count, evidence count, and linked findings together.",
    limitation: "A mapping is classification context, not proof that the full adversary technique occurred.",
    whatItShows: [
      {
        label: "Tactic groups",
        explanation: "Organize techniques by attacker objective such as Credential Access or Persistence.",
        example: "Password guessing appears under Credential Access rather than as an unstructured alert label.",
      },
      {
        label: "Technique cards",
        explanation: "Show technique ID, name, maximum finding severity, number of rules, and evidence coverage.",
        example: "T1110.001 Password Guessing can show one rule, ten evidence lines, and high severity.",
      },
      {
        label: "Finding pivots",
        explanation: "Short-ID buttons connect a technique back to the detections that created the mapping.",
        example: "Opening the T1110.001 finding lets you verify the failed-login lines instead of trusting the map alone.",
      },
    ],
    example: {
      scenario: "Compare T1110.001, T1078, and T1136.001 in the SSH sample.",
      observation: "The map shows password guessing, valid accounts, and local account creation across one incident.",
      interpretation: "This forms a plausible progression from credential attack to access and persistence, but the mapping comes from rule declarations.",
      nextStep: "Open each finding ID and confirm the underlying evidence and rule before describing an ATT&CK chain.",
    },
    controls: [
      {
        label: "Finding ID chip",
        kind: "button",
        action: "Selects a finding that contributed to the technique.",
        result: "The selection becomes active for Findings and Evidence; the MITRE view does not alter or create detections.",
      },
    ],
    steps: [
      { target: '[data-tour="nav-mitre"]', title: "MITRE map", body: "Open ATT&CK context derived from current deterministic findings." },
      { target: '[data-tour="mitre-techniques"]', title: "Read tactic and technique cards", body: "Compare ID, name, severity, contributing rules, and evidence coverage." },
      { target: '[data-tour="mitre-links"]', title: "Open contributing findings", body: "Each short-ID button selects a finding so the ATT&CK label can be validated against rule and evidence." },
    ],
  },
  {
    view: "reports",
    title: "Reports",
    purpose: "Turn the current in-memory incident into a reviewable, portable summary without creating server-side report history.",
    dataOrigin: "The public report is rendered from the selected incident, linked findings, and linked evidence in the current analysis response.",
    readingMethod: "Verify the selected incident, finding and evidence counts, redaction choice, and preview before downloading.",
    limitation: "Public demo reports are Markdown-only and disappear with the session unless downloaded.",
    whatItShows: [
      {
        label: "Report scope",
        explanation: "Shows which incident is selected and how many findings and evidence lines will be included.",
        example: "The SSH incident report can include four findings and the evidence lines linked to those findings.",
      },
      {
        label: "Privacy controls",
        explanation: "Lets the learner mask IPs, users, and hosts before generating output.",
        example: "198.51.100.10 and admin can be replaced with redacted values in the generated Markdown.",
      },
      {
        label: "Preview",
        explanation: "Shows the generated report for review before download.",
        example: "Check that observed evidence is separated from detection interpretation and recommended actions.",
      },
    ],
    example: {
      scenario: "Generate a redacted Markdown report for the SSH incident.",
      observation: "The preview includes incident context, findings, evidence, and masked sensitive identifiers.",
      interpretation: "The report is a portable investigation summary, not a stored case record or proof that every finding is true.",
      nextStep: "Review wording and evidence coverage, then download only if the preview is accurate and appropriately redacted.",
    },
    controls: [
      {
        label: "Markdown format",
        kind: "button",
        action: "Selects Markdown as the report format.",
        result: "Public demo keeps this as the only available format; selection does not generate a report.",
      },
      {
        label: "Redact IPs, users, and hosts",
        kind: "toggle",
        action: "Turns sensitive-identifier masking on or off for the next generation.",
        result: "It changes generated content only and does not modify the analysis result.",
      },
      {
        label: "Generate report",
        kind: "button",
        action: "Builds a session-only Markdown report for the selected incident.",
        result: "The preview is populated; no server-side report file or history entry is created.",
      },
      {
        label: "Download .md",
        kind: "button",
        action: "Downloads the already generated Markdown preview.",
        result: "The browser saves a local file. The button stays disabled until a report exists.",
      },
    ],
    steps: [
      { target: '[data-tour="nav-reports"]', title: "Session-only report", body: "Open the public Markdown report builder for the active incident." },
      { target: '[data-tour="report-controls"]', title: "Confirm report scope", body: "Check selected incident, finding count, evidence count, and Markdown format." },
      { target: '[data-tour="report-redaction"]', title: "Choose redaction", body: "The toggle masks IPs, users, and hosts in generated content without changing evidence." },
      { target: '[data-tour="report-generate"]', title: "Generate explicitly", body: "Generate report creates only an in-memory Markdown preview; it does not download or persist it." },
      { target: '[data-tour="report-download"]', title: "Download after review", body: "Download saves the existing preview locally and is disabled before generation." },
      { target: '[data-tour="report-preview"]', title: "Review the output", body: "Validate evidence, conclusions, recommendations, and redaction before keeping the file." },
    ],
  },
  {
    view: "library",
    title: "Detection library",
    purpose: "Teach how transparent deterministic detections work and how an analyst should challenge them.",
    dataOrigin: "The library is loaded from the versioned YAML rule set shipped with this TraceHawk build.",
    readingMethod: "Filter rules, select one, then read intent, matching logic, correlation behavior, current findings, false positives, and analyst next steps.",
    limitation: "Rules are bounded examples and do not replace a continuously maintained production detection program.",
    whatItShows: [
      {
        label: "Rule list",
        explanation: "Shows title, severity, description, category, confidence, MITRE technique, and whether the rule matched this analysis.",
        example: "ssh-bruteforce-001 can be marked found in current case after the SSH sample runs.",
      },
      {
        label: "Rule detail",
        explanation: "Explains identifiers, log types, correlation keys and gap, why it matters, what it looks for, false positives, and next steps.",
        example: "A brute-force rule may look for repeated failed logins grouped by source IP and username within a bounded window.",
      },
      {
        label: "Current findings",
        explanation: "Connects static rule documentation to matches in the current session.",
        example: "The detail can show the matched finding title, ten events, and high confidence.",
      },
    ],
    example: {
      scenario: "Open the SSH brute-force rule after running the SSH sample.",
      observation: "The rule is marked detected and documents its threshold, confidence, correlation family, false positives, and response steps.",
      interpretation: "The rule explains why the finding exists and what could make it benign; this is the core difference between transparent detection and a black-box verdict.",
      nextStep: "Compare the rule's look-for conditions with the selected finding and its ten raw evidence lines.",
    },
    controls: [
      {
        label: "Search detection rules",
        kind: "field",
        action: "Filters by rule ID, title, description, MITRE values, or log type.",
        result: "Only the visible rule list changes; current findings and analysis remain untouched.",
      },
      {
        label: "Detection category",
        kind: "selector",
        action: "Restricts the list to one rule category.",
        result: "The first remaining matching rule becomes the visible detail when necessary.",
      },
      {
        label: "Found only",
        kind: "toggle",
        action: "Shows only rules that produced findings in the current analysis.",
        result: "It is disabled before an analysis has matched any rules.",
      },
      {
        label: "Rule card",
        kind: "button",
        action: "Selects a rule from the filtered list.",
        result: "The detail panel updates to the rule's learning content and current matched findings.",
      },
    ],
    steps: [
      { target: '[data-tour="nav-library"]', title: "Detection library", body: "Open the versioned rules behind every public-demo finding." },
      { target: '[data-tour="library-filters"]', title: "Filter the curriculum", body: "Search, category, and Found only narrow the list without changing analysis data." },
      { target: '[data-tour="library-rules"]', title: "Select a rule", body: "Clicking a rule card updates the detail panel; a found badge links static logic to this session." },
      { target: '[data-tour="library-detail"]', title: "Learn and challenge the logic", body: "Read what the rule looks for, correlation behavior, false positives, current findings, and analyst next steps." },
    ],
  },
];

export function tutorialSection(view: WorkspaceView): TutorialSection {
  return TUTORIAL_SECTIONS.find((section) => section.view === view) ?? TUTORIAL_SECTIONS[0];
}
