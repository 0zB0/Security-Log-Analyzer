import { defineConfig, devices } from "@playwright/test";
import { existsSync } from "node:fs";


const localChromium = "/usr/bin/chromium-browser";
const chromiumPath = process.env.TRACEHAWK_CHROMIUM_PATH ??
  (existsSync(localChromium) ? localChromium : undefined);

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: "http://127.0.0.1:8000",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    launchOptions: chromiumPath ? { executablePath: chromiumPath } : undefined,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command:
      'npm run build && TRACEHAWK_WEB_DIST="$PWD/dist" ' +
      '"${TRACEHAWK_PYTHON:-../../.venv/bin/python}" -m uvicorn tracehawk_api.main:app ' +
      '--app-dir ../api --host 127.0.0.1 --port 8000 --no-access-log',
    url: "http://127.0.0.1:8000/api/health/ready",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
