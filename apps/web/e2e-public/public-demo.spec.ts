import { expect, test } from "@playwright/test";


test("keeps anonymous analysis session-only and blocks private capabilities", async ({
  page,
  request,
}) => {
  const status = await request.get("/api/public-demo/status");
  expect(status.status()).toBe(200);
  expect(status.headers()["cache-control"]).toBe("no-store, max-age=0");
  expect(await status.json()).toMatchObject({
    enabled: true,
    storage: "disabled",
    external_ai: false,
  });
  expect((await request.get("/api/analyze/runs")).status()).toBe(404);

  await page.goto("/");
  await expect(page.getByText("Public session-only demo")).toBeVisible();
  await expect(page.getByText("Session-only processing")).toBeVisible();
  await expect(page.getByRole("button", { name: "Case" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Live Monitor" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Local AI" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Settings" })).toHaveCount(0);

  await page.getByRole("button", { name: "Run demo" }).click();
  await expect(page.getByRole("heading", { name: "Incident desk" })).toBeVisible();
  await expect(page.getByText("Possible SSH credential compromise").first()).toBeVisible();
  await expect(page.getByText(/Auto-clear in/)).toBeVisible();

  await page.reload();
  await expect(page.getByText("No active result")).toBeVisible();
  await expect(page.getByText("No file selected").first()).toBeVisible();
});


test("uploads one browser-read text log and guides the visitor through help", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Browse...").setInputFiles({
    name: "auth.log",
    mimeType: "text/plain",
    buffer: Buffer.from(
      "Jul 08 09:10:20 host sshd[1]: Failed password for admin from 198.51.100.10 port 22 ssh2\n" +
        "Jul 08 09:10:21 host sshd[1]: Failed password for admin from 198.51.100.10 port 22 ssh2\n" +
        "Jul 08 09:10:22 host sshd[1]: Failed password for admin from 198.51.100.10 port 22 ssh2\n" +
        "Jul 08 09:10:23 host sshd[1]: Failed password for admin from 198.51.100.10 port 22 ssh2\n" +
        "Jul 08 09:10:24 host sshd[1]: Failed password for admin from 198.51.100.10 port 22 ssh2\n",
    ),
  });

  await expect(page.getByRole("heading", { name: "Incident desk" })).toBeVisible();
  await page.getByRole("button", { name: "Findings" }).click();
  await expect(page.getByRole("heading", { name: "Findings", level: 1 })).toBeVisible();
  await page.getByRole("button", { name: "Start Findings guided tour" }).click();
  await expect(page.getByRole("dialog")).toContainText("Findings: 1 / 3");
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.getByRole("dialog")).toContainText("Findings: 2 / 3");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);

  await page.getByRole("button", { name: "Tutorial" }).click();
  await expect(page).toHaveURL(/\/tutorial$/);
  await expect(page.getByRole("heading", { name: "TraceHawk guided tutorial" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Evidence: What this view shows" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Evidence: Buttons and controls on this view" }),
  ).toBeVisible();
  await expect(page.getByText("When used").first()).toBeVisible();
  await expect(page.getByText("Result").first()).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Start Evidence guided walkthrough" }),
  ).toBeVisible();
  const manifest = await page.request.get("/tutorial-videos/manifest.json");
  expect(manifest.status()).toBe(200);
  expect((await manifest.json()).map((video: { view: string }) => video.view)).toEqual([
    "upload",
    "incidents",
    "findings",
    "evidence",
    "entities",
    "mitre",
    "reports",
    "library",
  ]);
  await page.getByRole("button", { name: "Watch Evidence narrated video" }).click();
  const evidenceVideo = page.getByLabel("Evidence narrated tutorial video");
  await expect(evidenceVideo).toBeVisible();
  await expect(evidenceVideo.locator("source")).toHaveAttribute(
    "src",
    "/tutorial-videos/evidence.mp4",
  );
  await expect(evidenceVideo.locator("track")).toHaveAttribute(
    "src",
    "/tutorial-videos/evidence.en.vtt",
  );
});
