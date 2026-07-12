# TraceHawk Design System

Version: 0.9.0
Product: TraceHawk / Security Log Analyzer
Direction: darker OpenCode-inspired evidence console

## Reference

Primary reference:

- OpenCode DESIGN.md: https://getdesign.md/opencode.ai/design-md

Use OpenCode as a directional reference only. Do not copy its brand, page structure, cream marketing canvas, or full DESIGN.md content. Translate the useful qualities into this product:

- terminal-native developer tool feeling
- flat surfaces
- hairline borders
- restrained monochrome palette
- strong log/evidence treatment
- technical typography

## Product Intent

Security Log Analyzer should feel like an evidence-first security tool, not a glossy SOC dashboard, landing page, generic AI product, or BI template.

The first successful demo view should answer:

1. What suspicious behavior was detected?
2. Which exact log lines support it?
3. How severe and confident is the detection?
4. What should an analyst do next?

## Visual Direction

Use a black/white mono-first interface with severity as the primary color system.

Core qualities:

- near-black application shell
- off-white text
- muted gray secondary text
- 1px hairline borders
- compact panels with 4px to 6px radius
- no hero sections
- no decorative gradients
- no dominant cyan, purple, blue, green, or orange theme
- color only where it carries state or severity

Small cyan/white focus treatment is allowed for active controls, but it must not become the brand color.

## Color Tokens

```css
:root {
  color-scheme: dark;
  --bg: #050608;
  --bg-soft: #090b0f;
  --surface: #0d1117;
  --surface-raised: #11161d;
  --surface-elevated: #151b23;
  --line: #252b33;
  --line-strong: #3a424d;
  --text: #f2f4f8;
  --muted: #8b949e;
  --muted-strong: #c9d1d9;
  --focus: #d7fcff;
  --ok: #7ee787;
  --low: #79c0ff;
  --medium: #f2cc60;
  --high: #ffa657;
  --critical: #ff7b72;
}
```

Severity colors:

- critical: red
- high: orange
- medium: amber
- low: muted blue

Use severity colors in badges, evidence highlights, chart points, and small status marks only.

## Typography

Hybrid typography:

- Monospace for UI labels, navigation, buttons, badges, KPI values, rule IDs, line numbers, evidence, technical metadata.
- Sans-serif for longer analyst summary and explanatory text.
- Use tabular numerals for KPIs and counts.
- Avoid making every paragraph monospace; that reduces readability.

Recommended stacks:

```css
--font-ui: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
--font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
```

## Layout

The app is an operational tool. The first screen is the product, not a marketing intro.

Desktop after `Run demo`:

- top command/header with product path, version, auth, refresh
- compact intake bar with upload, analyze, run demo, exports
- telemetry strip with small counts
- evidence-first workbench:
  - findings table on the left
  - evidence pane on the right
  - side rail for incident note, severity, source distribution, and timeline

KPI counts are supporting telemetry, not the main hero.

Responsive order:

1. command/header
2. intake
3. telemetry strip
4. findings
5. evidence
6. incident note
7. severity/source/timeline

No horizontal overflow is acceptable on mobile.

## Terminal Restraint

Use moderate terminal cues:

- bracket section labels: `[intake]`, `[telemetry]`, `[findings]`, `[evidence]`, `[incident]`
- monospace metadata
- CLI-like empty copy
- log viewer with line numbers and rule markers

Avoid:

- ASCII art logos
- fake hacker copy
- excessive symbols
- terminal green as the dominant palette

## Components

### Command Header

Use the product path and version:

`SOC / Log Analyzer / Investigation`

Show:

- `TraceHawk v0.9.0`
- auth state
- data scope
- refresh action

### Intake

The intake bar should feel like a command strip:

- file input
- `Analyze`
- `Run demo`
- report exports

`Run demo` should be obvious when no file is loaded. It should stay secondary once a file is selected.

### Telemetry Strip

Small dense metrics:

- parsed lines
- detections
- incidents
- affected users

Use compact inline cells, not large dashboard cards.

### Findings Table

The findings table remains the full list. It must support scanning:

- detection title
- rule ID
- summary
- severity
- evidence count
- confidence

Hover or click on a finding should highlight related evidence lines. The table stays intact.

### Evidence Pane

The evidence pane is the strongest visual element.

Rules:

- monospace
- near-black inner background
- visible line numbers
- rule headers
- related evidence lines can be highlighted
- long lines wrap without breaking the page
- selected evidence uses severity color as a small left border or soft background, not a full bright fill

### Incident Note

The incident note uses sans-serif for readability. It should feel like an analyst note, not marketing or AI copy.

### Source Distribution

Until real GeoIP enrichment exists, call it source distribution, not attacker map. Keep it subdued.

## Interaction Rules

- Search filters findings by title, rule, summary, rationale, severity, confidence, and MITRE text.
- Clicking a finding selects its exact backend-linked evidence lines.
- `/` focuses search; `Escape` clears it and returns focus to the workspace.
- Refresh reloads the current workspace and does not silently rerun an upload.
- Exports are disabled until results exist.

## Implementation Notes

- Keep top-level coordination in `apps/web/src/app/main.tsx` and panel-local behavior in
  `apps/web/src/features/workspace/`.
- Keep domain response types derived from the generated FastAPI contract.
- Favor semantic CSS variables and component classes.
- Avoid inline style unless runtime data makes a class impractical.
- Verify with TypeScript build, interaction/axe tests, and Playwright Chromium workflows.
