import { expect, test } from "@playwright/test";


test("runs an evidence-backed investigation and opens the report workflow", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByText("Local admin mode")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Investigation workspace" })).toBeVisible();

  await page.getByRole("button", { name: "Run demo" }).click();
  await expect(page.getByRole("heading", { name: "Incident desk" })).toBeVisible();
  await expect(page.getByText("Possible SSH credential compromise").first()).toBeVisible();
  await expect(page.getByText(/lines loaded/)).toBeVisible();

  await page.getByRole("button", { name: "Reports" }).click();
  await expect(page.getByRole("heading", { name: "Reports" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Incident report" })).toBeVisible();
  await page.getByRole("button", { name: "Generate report" }).click();
  await expect(page.getByRole("button", { name: "Download .md" })).toBeEnabled();
  await expect(page.locator(".report-preview pre")).toContainText("TraceHawk Incident Report");
});


test("exposes admin-only host controls in local admin mode", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("button", { name: "Live Monitor" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Settings" })).toBeVisible();

  await page.getByRole("button", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { name: "Local AI settings" })).toBeVisible();
  await page.getByRole("button", { name: "Live Monitor" }).click();
  await expect(page.getByRole("heading", { name: "Live monitor" })).toBeVisible();
  await expect(page.getByText("0/0 retained lines")).toBeVisible();
});


test("investigates the real-lab case through source and cross-source evidence", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Real lab case" }).click();
  await expect(page.getByRole("heading", { name: "Case investigation" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Sources" })).toBeVisible();
  await expect(page.locator(".source-row").filter({ hasText: "conn.log" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Cross-source links" })).toBeVisible();
  await expect(page.getByText(/Suricata and Zeek both observed HTTP path/).first()).toBeVisible();
  await expect(page.locator(".case-evidence-card")).toHaveCount(2);
  await expect(page.locator(".case-evidence-card code").first()).not.toBeEmpty();
});


test("pivots from a deterministic finding to exact raw evidence", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Run demo" }).click();
  await expect(page.getByRole("heading", { name: "Incident desk" })).toBeVisible();
  await page.getByRole("button", { name: "Evidence" }).click();
  await expect(page.getByRole("heading", { name: "Evidence review" })).toBeVisible();
  const search = page.getByRole("textbox", { name: "Global investigation search" });
  await search.fill("no-such-finding");
  await expect(page.getByText("No findings match the current search.")).toBeVisible();
  await search.fill("T1110.001");
  await expect(page.getByText("SSH brute force attempt").first()).toBeVisible();
  await expect(page.locator(".evidence-line-expanded").first()).toContainText(
    "Failed password for admin",
  );
  await expect(page.locator(".hash-row code").first()).toHaveText(/[a-f0-9]{16}/);
});


test("shows a rejected action and recovers on the next authorized request", async ({ page }) => {
  await page.route("**/api/analyze/demo", async (route) => {
    await route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Demo action rejected by policy" }),
    });
  });
  await page.goto("/");

  await page.getByRole("button", { name: "Run demo" }).click();
  await expect(page.getByText("Demo action rejected by policy")).toBeVisible();

  await page.unroute("**/api/analyze/demo");
  await page.getByRole("button", { name: "Run demo" }).click();
  await expect(page.getByRole("heading", { name: "Incident desk" })).toBeVisible();
  await expect(page.getByText("Demo action rejected by policy")).toHaveCount(0);
});
