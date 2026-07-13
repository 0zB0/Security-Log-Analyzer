import { chromium } from "@playwright/test";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";


const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(webRoot, "../..");
const outputDirectory = resolve(webRoot, "public/tutorial-videos");
const baseUrl = process.env.TRACEHAWK_BASE_URL || "http://127.0.0.1:8001";
const chromePath = process.env.TRACEHAWK_CHROMIUM_PATH;
const pythonPath = process.env.TRACEHAWK_PYTHON || resolve(repositoryRoot, ".venv/bin/python");
const voice = process.env.TRACEHAWK_TUTORIAL_VOICE || "en-US-GuyNeural";
const requestedViews = new Set(
  (process.env.TRACEHAWK_TUTORIAL_VIEWS || "")
    .split(",")
    .map((view) => view.trim())
    .filter(Boolean),
);
const actionPaddingSeconds = 1.4;
const tempDirectory = await mkdtemp(resolve(tmpdir(), "tracehawk-tutorial-videos-"));

const storyboards = [
  {
    view: "upload",
    title: "Upload and investigation intake",
    description: "Load a safe sample, read analysis totals, and understand the session-only privacy boundary.",
    segments: [
      ["none", "Welcome to the Upload tutorial. This view starts an investigation and shows what the parser, detection engine, and correlator produced before you draw conclusions."],
      ["run-demo", "We click Run demo to load the fixed, sanitized SSH compromise sample. The browser sends it once to the stateless endpoint, and TraceHawk opens the strongest incident."],
      ["open-upload", "We return to Upload. The intake strip reports the parser and finding count, while the metric cards separate raw lines, parsed events, findings, and incidents."],
      ["point-intake", "Browse reads one supported text log. The sample selector chooses a safe scenario, Run sample executes it, and Markdown opens the report builder without generating a report."],
      ["click-upload-cards", "The investigation preview connects incident cards, finding cards, and exact evidence. Clicking a card changes selection only; it never repeats or stores the analysis."],
      ["point-privacy", "The privacy banner is the boundary to remember. Clear session, refresh, tab close, or thirty minutes of inactivity removes the browser-held result."],
    ],
  },
  {
    view: "incidents",
    title: "Incident prioritization",
    description: "Read correlation score, linked findings, entities, and event chronology as one reviewable story.",
    segments: [
      ["none", "Welcome to the Incidents tutorial. Incidents group related deterministic findings into a reviewable story, but a high score is still a priority signal rather than proof."],
      ["run-demo", "We load the sanitized SSH sample. Repeated failures, a later success, and privileged account activity are correlated into one possible credential compromise."],
      ["open-incidents", "The incident list ranks stories by severity, score, finding count, techniques, and shared entities. Clicking an incident card updates the detail panel."],
      ["click-incident", "We select the incident and verify the scoring rationale. TraceHawk exposes each score component instead of presenting an unexplained risk number."],
      ["click-linked-finding", "A linked finding button selects one contributing detection. That selection is preserved when we move to Findings or Evidence for validation."],
      ["point-timeline", "Finally, we read the timeline in order. Ten failures precede an accepted login and a privileged command. The sequence is the key signal, not the score alone."],
    ],
  },
  {
    view: "findings",
    title: "Deterministic finding review",
    description: "Select a rule match, inspect its reason and evidence, and open the transparent rule definition.",
    segments: [
      ["none", "Welcome to the Findings tutorial. A finding is one deterministic rule match. Review it independently before accepting the incident that contains it."],
      ["run-demo", "We load the fixed SSH sample so every learner sees the same evidence and the same four findings."],
      ["open-findings", "The list shows title, severity, confidence, event count, and MITRE technique. Clicking a finding card changes the evidence preview beside it."],
      ["click-finding", "We select a finding and compare its reason with the numbered raw lines. Confidence describes the rule match; it does not remove the possibility of a false positive."],
      ["click-finding-rule", "We click Rule to open the exact versioned detection definition. The Library explains matching logic, correlation behavior, false positives, and recommended analyst steps."],
      ["return-findings", "Returning to Findings preserves the selected detection. The workflow is deliberate: signal, evidence, rule logic, and only then a conclusion."],
    ],
  },
  {
    view: "evidence",
    title: "Raw evidence validation",
    description: "Connect a selected finding to exact source lines, rule metadata, MITRE context, and hashes.",
    segments: [
      ["none", "Welcome to the Evidence tutorial. This view keeps raw log lines beside the detection that references them so the analyst can challenge the match."],
      ["run-demo", "We load the sanitized SSH sample. No uploaded evidence is written to public history or sent to external artificial intelligence."],
      ["open-evidence", "The finding selector controls the evidence context. Clicking a finding card updates both the raw viewer and the metadata panel."],
      ["click-evidence-finding", "We select the brute-force context and inspect repeated failed logins for the same user and source address. Changing client ports is normal and does not imply different attackers."],
      ["point-evidence-raw", "Line numbers and untouched text show what the parser and rule actually received. The view does not replace evidence with an artificial-intelligence summary."],
      ["point-evidence-metadata", "The metadata panel connects rule, severity, confidence, event count, MITRE technique, and per-line content hashes. These hashes prove consistency inside this analysis, not external chain of custody."],
      ["click-evidence-rule", "Clicking Rule opens the transparent definition behind the selected evidence. This completes the path from source line to detection logic."],
    ],
  },
  {
    view: "entities",
    title: "Entity pivots",
    description: "Prioritize extracted users, addresses, and systems, then pivot to their incidents and findings.",
    segments: [
      ["none", "Welcome to the Entities tutorial. Entities connect users, addresses, hosts, services, paths, domains, and containers across the current analysis."],
      ["run-demo", "We load the sanitized SSH sample to create a consistent set of users, source addresses, findings, and one correlated incident."],
      ["open-entities", "Each card shows entity type, normalized value, risk, event volume, finding count, and incident count. These values prioritize pivots; they do not provide external reputation."],
      ["click-entity-incident", "We click the incident title chip. It selects the related story without re-running analysis, so Incidents and Reports use the same context."],
      ["click-entity-finding", "A short finding identifier selects the linked detection. Findings and Evidence will now open with that exact signal active."],
      ["point-entity-cards", "Shared entities explain why events were grouped. Always follow the links back to chronology, rule logic, and raw evidence before attributing activity."],
    ],
  },
  {
    view: "mitre",
    title: "MITRE ATT&CK context",
    description: "Read tactics and techniques as classification context and validate every mapping through its findings.",
    segments: [
      ["none", "Welcome to the MITRE tutorial. This view organizes current findings by ATT and CK tactics and techniques. A mapping is classification context, not proof that the full technique occurred."],
      ["run-demo", "We load the sanitized SSH sample. Its rules map password guessing, valid accounts, and local account creation into one possible progression."],
      ["open-mitre", "Technique cards show the identifier, name, maximum severity, contributing rules, and evidence coverage under each attacker objective."],
      ["point-mitre-techniques", "For example, T eleven ten point zero zero one represents password guessing. Its evidence count comes from the current rule matches, not from an external threat-intelligence verdict."],
      ["click-mitre-finding", "We click a short finding identifier to select the detection that created this mapping. Findings and Evidence preserve that selection for validation."],
      ["point-mitre-links", "Use the map to structure investigation language, then verify every label against rule logic and raw evidence before describing an attack chain."],
    ],
  },
  {
    view: "reports",
    title: "Session-only Markdown reports",
    description: "Confirm report scope, apply redaction, generate explicitly, review, and download locally.",
    segments: [
      ["none", "Welcome to the Reports tutorial. The public demo builds a portable Markdown summary from the active in-memory incident without creating report history."],
      ["run-demo", "We load the sanitized SSH sample. The selected incident, its four findings, and linked evidence define the report scope."],
      ["open-reports", "The control panel shows the active incident and available format. Public mode supports Markdown only, and opening this view does not generate anything."],
      ["toggle-redaction", "We enable redaction. The next report masks IP addresses, users, and hosts while leaving the analysis result unchanged."],
      ["generate-report", "We click Generate report. TraceHawk creates an in-memory preview; it does not persist a server-side report or download a file automatically."],
      ["point-report-preview", "We review evidence, conclusions, recommendations, and redaction in the preview. Download dot M D becomes available only after generation and saves the reviewed content locally."],
    ],
  },
  {
    view: "library",
    title: "Detection library",
    description: "Filter transparent rules, select one, and compare its logic and false positives with current findings.",
    segments: [
      ["none", "Welcome to the Detection Library tutorial. The Library turns every public finding into inspectable, versioned rule logic instead of a black-box verdict."],
      ["run-demo", "We load the sanitized SSH sample so the Library can mark which rules produced findings in this session."],
      ["open-library", "The rule list shows severity, confidence, category, log types, MITRE mapping, and whether a rule matched the current analysis."],
      ["search-library", "We type S S H into search. Search filters the visible curriculum only; it does not alter findings or rerun detection."],
      ["filter-library", "We choose the Auth category and enable Found only. These controls narrow the list to relevant rules that matched this sample."],
      ["click-library-rule", "Clicking a rule card updates the detail panel. Here we read what the rule looks for, correlation behavior, false positives, current findings, and analyst next steps."],
      ["point-library-detail", "The learning loop ends by comparing the rule conditions with the selected finding and its raw evidence. Transparent logic makes the detection challengeable."],
    ],
  },
];

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || repositoryRoot,
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} failed with exit code ${result.status}.`);
  }
  return result.stdout?.trim() || "";
}

async function waitForReady(url, timeoutMs = 120_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Server is still starting.
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 500));
  }
  throw new Error(`Timed out waiting for ${url}.`);
}

function secondsToVtt(value) {
  const milliseconds = Math.max(0, Math.round(value * 1000));
  const hours = Math.floor(milliseconds / 3_600_000);
  const minutes = Math.floor((milliseconds % 3_600_000) / 60_000);
  const seconds = Math.floor((milliseconds % 60_000) / 1000);
  const millis = milliseconds % 1000;
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}.${String(millis).padStart(3, "0")}`;
}

async function synthesizeSegments(storyboard, directory) {
  const segments = [];
  for (const [index, [, narration]] of storyboard.segments.entries()) {
    const mediaPath = resolve(directory, `${String(index + 1).padStart(2, "0")}.mp3`);
    run("uvx", [
      "--from", "edge-tts==7.2.8", "edge-tts",
      "--voice", voice,
      "--rate=-4%",
      "--text", narration,
      "--write-media", mediaPath,
    ]);
    const probe = JSON.parse(run("ffprobe", [
      "-v", "error",
      "-show_entries", "format=duration",
      "-of", "json",
      mediaPath,
    ], { capture: true }));
    segments.push({ narration, mediaPath, duration: Number(probe.format.duration) });
  }
  return segments;
}

function buildNarrationTrack(segments, outputPath) {
  const args = ["-hide_banner", "-loglevel", "error", "-y"];
  for (const segment of segments) {
    args.push("-f", "lavfi", "-t", String(actionPaddingSeconds), "-i", "anullsrc=r=24000:cl=mono");
    args.push("-i", segment.mediaPath);
  }
  const labels = segments.flatMap((_, index) => [`[${index * 2}:a]`, `[${index * 2 + 1}:a]`]).join("");
  args.push(
    "-filter_complex", `${labels}concat=n=${segments.length * 2}:v=0:a=1[a]`,
    "-map", "[a]",
    "-ar", "24000",
    "-ac", "1",
    outputPath,
  );
  run("ffmpeg", args);
}

async function writeCaptions(storyboard, segments, outputPath) {
  let cursor = 0;
  const cues = ["WEBVTT", ""];
  for (const [index, segment] of segments.entries()) {
    const start = cursor + actionPaddingSeconds;
    const end = start + segment.duration;
    cues.push(String(index + 1));
    cues.push(`${secondsToVtt(start)} --> ${secondsToVtt(end)}`);
    cues.push(segment.narration);
    cues.push("");
    cursor = end;
  }
  await writeFile(outputPath, cues.join("\n"));
  return cursor;
}

async function installRecorderOverlay(page) {
  await page.addStyleTag({ content: `
    #tracehawk-recorder-cursor {
      position: fixed; left: 24px; top: 24px; z-index: 2147483647; width: 22px; height: 22px;
      border: 3px solid #ffffff; border-radius: 999px; background: #3ccf91;
      box-shadow: 0 0 0 3px rgba(60, 207, 145, .32), 0 6px 20px rgba(0, 0, 0, .65);
      pointer-events: none; transition: left .55s ease, top .55s ease, transform .16s ease;
    }
    #tracehawk-recorder-cursor.tracehawk-click { transform: scale(.62); background: #f5c451; }
    #tracehawk-recorder-caption {
      position: fixed; left: 50%; bottom: 24px; z-index: 2147483646; width: min(980px, calc(100vw - 80px));
      transform: translateX(-50%); border: 1px solid rgba(121, 192, 255, .65); border-radius: 10px;
      background: rgba(5, 10, 16, .94); color: #eef6ff; box-shadow: 0 16px 50px rgba(0, 0, 0, .58);
      font: 600 21px/1.42 system-ui, sans-serif; padding: 15px 19px; text-align: center; pointer-events: none;
    }
    #tracehawk-recorder-label {
      position: fixed; right: 18px; top: 14px; z-index: 2147483646; border: 1px solid #314255;
      border-radius: 999px; background: rgba(5, 10, 16, .9); color: #9eb2c7;
      font: 700 12px/1.2 ui-monospace, monospace; padding: 7px 10px; pointer-events: none;
    }
  ` });
  await page.evaluate(() => {
    const cursor = document.createElement("div");
    cursor.id = "tracehawk-recorder-cursor";
    const caption = document.createElement("div");
    caption.id = "tracehawk-recorder-caption";
    caption.setAttribute("aria-hidden", "true");
    const label = document.createElement("div");
    label.id = "tracehawk-recorder-label";
    label.textContent = "TRACEHAWK LEARNING TOOL";
    document.body.append(cursor, caption, label);
  });
}

async function showCaption(page, narration) {
  await page.evaluate((text) => {
    const caption = document.querySelector("#tracehawk-recorder-caption");
    if (caption) caption.textContent = text;
  }, narration);
}

async function moveCursor(page, locator) {
  await locator.scrollIntoViewIfNeeded();
  const box = await locator.boundingBox();
  if (!box) throw new Error("Recorder target is not visible.");
  const x = Math.min(1268, Math.max(12, box.x + box.width / 2));
  const y = Math.min(708, Math.max(12, box.y + Math.min(box.height / 2, 90)));
  await page.evaluate(({ x, y }) => {
    const cursor = document.querySelector("#tracehawk-recorder-cursor");
    if (cursor instanceof HTMLElement) {
      cursor.style.left = `${x - 11}px`;
      cursor.style.top = `${y - 11}px`;
    }
  }, { x, y });
  await page.waitForTimeout(650);
  return { x, y };
}

async function point(page, selector) {
  const locator = page.locator(selector).first();
  await moveCursor(page, locator);
  await locator.evaluate((element) => {
    element.animate(
      [{ boxShadow: "0 0 0 0 rgba(121,192,255,.8)" }, { boxShadow: "0 0 0 7px rgba(121,192,255,0)" }],
      { duration: 900, iterations: 2 },
    );
  });
}

async function clickLocator(page, locator) {
  const { x, y } = await moveCursor(page, locator);
  await page.evaluate(() => document.querySelector("#tracehawk-recorder-cursor")?.classList.add("tracehawk-click"));
  await page.mouse.click(x, y);
  await page.waitForTimeout(180);
  await page.evaluate(() => document.querySelector("#tracehawk-recorder-cursor")?.classList.remove("tracehawk-click"));
}

async function clickTour(page, selector, childSelector = "button") {
  await clickLocator(page, page.locator(selector).locator(childSelector).first());
}

async function executeAction(page, action) {
  switch (action) {
    case "none":
      return;
    case "run-demo":
      await clickLocator(page, page.getByRole("button", { name: "Run demo", exact: true }));
      await page.getByRole("heading", { name: "Incident desk", exact: true }).waitFor();
      return;
    case "open-upload":
      await clickLocator(page, page.getByRole("button", { name: "Upload", exact: true }));
      await page.getByRole("heading", { name: "Investigation workspace", exact: true }).waitFor();
      return;
    case "point-intake":
      return point(page, '[data-tour="upload-intake"]');
    case "click-upload-cards":
      await clickTour(page, '[data-tour="view-upload-content"]');
      return;
    case "point-privacy":
      return point(page, '[data-tour="session-privacy"]');
    case "open-incidents":
      await clickLocator(page, page.getByRole("button", { name: "Incidents", exact: true }));
      return;
    case "click-incident":
      await clickTour(page, '[data-tour="incident-list"]');
      return;
    case "click-linked-finding":
      await clickTour(page, '[data-tour="incident-linked-findings"]');
      return;
    case "point-timeline":
      return point(page, '[data-tour="incident-timeline"]');
    case "open-findings":
    case "return-findings":
      await clickLocator(page, page.getByRole("button", { name: "Findings", exact: true }));
      return;
    case "click-finding":
      await clickTour(page, '[data-tour="finding-list"]');
      return;
    case "click-finding-rule":
      await clickLocator(page, page.locator('[data-tour="finding-list"]').getByRole("button", { name: "Rule", exact: true }).first());
      await page.getByRole("heading", { name: "Detection library", exact: true }).waitFor();
      return;
    case "open-evidence":
      await clickLocator(page, page.getByRole("button", { name: "Evidence", exact: true }));
      return;
    case "click-evidence-finding":
      await clickTour(page, '[data-tour="evidence-findings"]');
      return;
    case "point-evidence-raw":
      return point(page, '[data-tour="evidence-raw"]');
    case "point-evidence-metadata":
      return point(page, '[data-tour="evidence-metadata"]');
    case "click-evidence-rule":
      await clickLocator(page, page.locator('[data-tour="evidence-findings"]').getByRole("button", { name: "Rule", exact: true }).first());
      return;
    case "open-entities":
      await clickLocator(page, page.getByRole("button", { name: "Entities", exact: true }));
      return;
    case "click-entity-incident":
      await clickTour(page, '[data-tour="entity-links"]');
      return;
    case "click-entity-finding": {
      const links = page.locator('[data-tour="entity-links"]').first().getByRole("button");
      await clickLocator(page, links.nth(Math.min(1, (await links.count()) - 1)));
      return;
    }
    case "point-entity-cards":
      return point(page, '[data-tour="entity-cards"]');
    case "open-mitre":
      await clickLocator(page, page.getByRole("button", { name: "MITRE", exact: true }));
      return;
    case "point-mitre-techniques":
      return point(page, '[data-tour="mitre-techniques"]');
    case "click-mitre-finding":
      await clickTour(page, '[data-tour="mitre-links"]');
      return;
    case "point-mitre-links":
      return point(page, '[data-tour="mitre-links"]');
    case "open-reports":
      await clickLocator(page, page.getByRole("button", { name: "Reports", exact: true }));
      return;
    case "toggle-redaction":
      await clickLocator(page, page.getByRole("checkbox", { name: /Redact IPs, users, and hosts/i }));
      return;
    case "generate-report":
      await clickLocator(page, page.getByRole("button", { name: "Generate report", exact: true }));
      await page.getByRole("button", { name: "Download .md", exact: true }).waitFor({ state: "visible" });
      return;
    case "point-report-preview":
      return point(page, '[data-tour="report-preview"]');
    case "open-library":
      await clickLocator(page, page.getByRole("button", { name: "Library", exact: true }));
      return;
    case "search-library": {
      const search = page.getByRole("textbox", { name: "Search detection rules", exact: true });
      await moveCursor(page, search);
      await search.fill("ssh");
      return;
    }
    case "filter-library": {
      const category = page.getByRole("combobox", { name: "Detection category", exact: true });
      await moveCursor(page, category);
      await category.selectOption({ label: "Auth" });
      const foundOnly = page.getByRole("checkbox", { name: "Found only", exact: true });
      await clickLocator(page, foundOnly);
      return;
    }
    case "click-library-rule":
      await clickTour(page, '[data-tour="library-rules"]');
      return;
    case "point-library-detail":
      return point(page, '[data-tour="library-detail"]');
    default:
      throw new Error(`Unknown storyboard action: ${action}`);
  }
}

async function recordStoryboard(browser, storyboard, segments, directory) {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    recordVideo: { dir: directory, size: { width: 1280, height: 720 } },
    colorScheme: "dark",
  });
  const page = await context.newPage();
  await page.goto(baseUrl);
  await page.getByText("Public session-only demo", { exact: true }).waitFor();
  await installRecorderOverlay(page);
  const video = page.video();

  for (const [index, [action]] of storyboard.segments.entries()) {
    await showCaption(page, segments[index].narration);
    const started = performance.now();
    await executeAction(page, action);
    const remainingPadding = actionPaddingSeconds * 1000 - (performance.now() - started);
    if (remainingPadding > 0) await page.waitForTimeout(remainingPadding);
    await page.waitForTimeout(segments[index].duration * 1000);
  }

  await page.close();
  const rawVideoPath = await video.path();
  await context.close();
  return rawVideoPath;
}

function encodeVideo(rawVideoPath, narrationPath, outputPath) {
  run("ffmpeg", [
    "-hide_banner",
    "-loglevel", "error",
    "-y",
    "-i", rawVideoPath,
    "-i", narrationPath,
    "-map", "0:v:0",
    "-map", "1:a:0",
    "-c:v", "libx264",
    "-preset", "medium",
    "-crf", "29",
    "-pix_fmt", "yuv420p",
    "-r", "24",
    "-c:a", "aac",
    "-b:a", "96k",
    "-movflags", "+faststart",
    "-shortest",
    outputPath,
  ]);
}

let browser;
try {
  await mkdir(outputDirectory, { recursive: true });
  run("npm", ["run", "build"], { cwd: webRoot });
  browser = await chromium.launch({
    headless: true,
    ...(chromePath ? { executablePath: chromePath } : {}),
  });

  const selectedStoryboards = requestedViews.size
    ? storyboards.filter((storyboard) => requestedViews.has(storyboard.view))
    : storyboards;
  if (!selectedStoryboards.length) {
    throw new Error(`No tutorial views matched: ${[...requestedViews].join(", ")}`);
  }
  for (const storyboard of selectedStoryboards) {
    process.stdout.write(`Generating ${storyboard.view} tutorial...\n`);
    const storyboardDirectory = resolve(tempDirectory, storyboard.view);
    await mkdir(storyboardDirectory, { recursive: true });
    const segments = await synthesizeSegments(storyboard, storyboardDirectory);
    const narrationPath = resolve(storyboardDirectory, "narration.wav");
    const captionsPath = resolve(outputDirectory, `${storyboard.view}.en.vtt`);
    buildNarrationTrack(segments, narrationPath);
    await writeCaptions(storyboard, segments, captionsPath);
    const server = spawn(pythonPath, [
      "-m", "uvicorn", "tracehawk_api.main:app",
      "--app-dir", resolve(repositoryRoot, "apps/api"),
      "--host", "127.0.0.1",
      "--port", "8001",
      "--no-access-log",
    ], {
      cwd: repositoryRoot,
      env: {
        ...process.env,
        TRACEHAWK_WEB_DIST: resolve(webRoot, "dist"),
        TRACEHAWK_DEPLOYMENT_PROFILE: "public_demo",
        TRACEHAWK_AUTH_MODE: "disabled",
        TRACEHAWK_LLM_PROVIDER: "mock",
        TRACEHAWK_DB_PATH: resolve(storyboardDirectory, "public-demo-disabled.db"),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    try {
      await waitForReady(`${baseUrl}/api/health/ready`);
      const rawVideoPath = await recordStoryboard(browser, storyboard, segments, storyboardDirectory);
      const outputPath = resolve(outputDirectory, `${storyboard.view}.mp4`);
      encodeVideo(rawVideoPath, narrationPath, outputPath);
    } finally {
      server.kill("SIGTERM");
      await new Promise((resolveExit) => server.once("exit", resolveExit));
    }
  }
  const manifest = [];
  for (const storyboard of storyboards) {
    const outputPath = resolve(outputDirectory, `${storyboard.view}.mp4`);
    const probe = JSON.parse(run("ffprobe", [
      "-v", "error",
      "-show_entries", "format=duration",
      "-of", "json",
      outputPath,
    ], { capture: true }));
    manifest.push({
      view: storyboard.view,
      title: storyboard.title,
      description: storyboard.description,
      duration_seconds: Number(Number(probe.format.duration).toFixed(1)),
      video: `/tutorial-videos/${storyboard.view}.mp4`,
      captions: `/tutorial-videos/${storyboard.view}.en.vtt`,
      language: "en",
      voice,
    });
  }
  await writeFile(resolve(outputDirectory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  run("npm", ["run", "build"], { cwd: webRoot });
  process.stdout.write(`Generated ${manifest.length} narrated tutorial videos.\n`);
} finally {
  await browser?.close();
  await rm(tempDirectory, { recursive: true, force: true });
}
