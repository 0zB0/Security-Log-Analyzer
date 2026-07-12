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
});
