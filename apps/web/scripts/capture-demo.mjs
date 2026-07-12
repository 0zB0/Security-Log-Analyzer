import { chromium } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";


const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "../../..");
const outputDirectory = resolve(repositoryRoot, "docs/assets/demo");
const caseProofDirectory = resolve(repositoryRoot, "docs/proof-pack/current-case-investigation-ux");
const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.TRACEHAWK_CHROMIUM_PATH || undefined,
});
const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });

async function clickButton(name) {
  const button = page.getByRole("button", { name, exact: true });
  if ((await button.count()) !== 1) {
    throw new Error(`Expected one ${name} button.`);
  }
  await button.click();
}

async function capture(filename) {
  await page.waitForTimeout(400);
  await page.evaluate(() => {
    window.scrollTo(0, 0);
    for (const element of document.querySelectorAll("*")) {
      if (element.scrollTop) element.scrollTop = 0;
      if (element.scrollLeft) element.scrollLeft = 0;
    }
  });
  await page.screenshot({ path: resolve(outputDirectory, filename) });
}

try {
  await mkdir(outputDirectory, { recursive: true });
  await mkdir(caseProofDirectory, { recursive: true });
  await page.goto(process.env.TRACEHAWK_BASE_URL || "http://127.0.0.1:8000/");
  await page.getByText("Local admin mode", { exact: true }).waitFor();

  await clickButton("Run demo");
  await page.getByRole("heading", { name: "Incident desk", exact: true }).waitFor();

  await clickButton("Upload");
  await page.getByRole("heading", { name: "Investigation workspace", exact: true }).waitFor();
  await capture("01-upload-analysis.png");

  await clickButton("Incidents");
  await page.getByRole("heading", { name: "Incident desk", exact: true }).waitFor();
  await capture("02-incident-correlation.png");

  await clickButton("Reports");
  await page.getByRole("heading", { name: "Reports", exact: true }).waitFor();
  await clickButton("Generate report");
  await page.getByRole("button", { name: "Download .md", exact: true }).waitFor();
  await capture("03-report-export.png");

  await clickButton("Real lab case");
  await page.getByRole("heading", { name: "Case investigation", exact: true }).waitFor();
  await capture("04-case-correlation.png");
  await page.screenshot({ path: resolve(caseProofDirectory, "case-workbench.png") });

  await clickButton("Library");
  await page.getByRole("heading", { name: "Detection library", exact: true }).waitFor();
  const foundOnly = page.getByRole("checkbox", { name: "Found only", exact: true });
  if ((await foundOnly.count()) !== 1) {
    throw new Error("Expected one Found only checkbox.");
  }
  await foundOnly.check();
  await page.waitForTimeout(400);
  await page.evaluate(() => {
    window.scrollTo(0, 0);
    for (const element of document.querySelectorAll("*")) {
      if (element.scrollTop) element.scrollTop = 0;
      if (element.scrollLeft) element.scrollLeft = 0;
    }
  });
  await page.waitForTimeout(400);
  await page.screenshot({ path: resolve(caseProofDirectory, "library-current-case.png") });
} finally {
  await browser.close();
}
