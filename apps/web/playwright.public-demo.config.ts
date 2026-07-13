import { defineConfig, devices } from "@playwright/test";
import { existsSync } from "node:fs";


const localChromium = "/usr/bin/chromium-browser";
const chromiumPath = process.env.TRACEHAWK_CHROMIUM_PATH ??
  (existsSync(localChromium) ? localChromium : undefined);

export default defineConfig({
  testDir: "./e2e-public",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI
    ? [["github"], ["html", { open: "never", outputFolder: "playwright-report-public" }]]
    : [["list"], ["html", { open: "never", outputFolder: "playwright-report-public" }]],
  use: {
    baseURL: "http://127.0.0.1:8001",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    launchOptions: chromiumPath ? { executablePath: chromiumPath } : undefined,
  },
  projects: [
    {
      name: "chromium-public-demo",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command:
      'npm run build && TRACEHAWK_WEB_DIST="$PWD/dist" ' +
      'TRACEHAWK_DEPLOYMENT_PROFILE=public_demo TRACEHAWK_AUTH_MODE=disabled ' +
      'TRACEHAWK_LLM_PROVIDER=mock TRACEHAWK_DB_PATH=/tmp/tracehawk-public-e2e.db ' +
      '"${TRACEHAWK_PYTHON:-../../.venv/bin/python}" -m uvicorn tracehawk_api.main:app ' +
      '--app-dir ../api --host 127.0.0.1 --port 8001 --no-access-log',
    url: "http://127.0.0.1:8001/api/health/ready",
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
