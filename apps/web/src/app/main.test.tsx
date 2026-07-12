import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  analyzeDemo,
  getAssistantStatus,
  getAuthStatus,
  listIncidentNotes,
} from "../lib/api";
import { analysisFixture } from "../test/workspaceFixtures";
import { App } from "./main";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    analyzeDemo: vi.fn(),
    getAssistantStatus: vi.fn(),
    getAuthStatus: vi.fn(),
    listIncidentNotes: vi.fn(),
  };
});

const mockedAnalyzeDemo = vi.mocked(analyzeDemo);
const mockedAssistantStatus = vi.mocked(getAssistantStatus);
const mockedAuthStatus = vi.mocked(getAuthStatus);
const mockedListNotes = vi.mocked(listIncidentNotes);

describe("application investigation workflow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedAuthStatus.mockResolvedValue({
      authenticated: false,
      email: null,
      allowed: true,
      role: "admin",
      auth_mode: "disabled",
      allowlist_enabled: false,
      local_admin: true,
    });
    mockedAssistantStatus.mockResolvedValue({
      enabled: false,
      provider: "mock",
      url: "",
      model: null,
      available: false,
      installed_models: [],
      error: null,
    });
    mockedListNotes.mockResolvedValue([]);
  });

  it("runs the demo and moves from empty intake to an evidence-backed incident", async () => {
    mockedAnalyzeDemo.mockResolvedValue(analysisFixture);
    render(<App />);

    expect(screen.getAllByText("No file selected").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: /^run demo$/i }));

    await waitFor(() => expect(mockedAnalyzeDemo).toHaveBeenCalledOnce());
    expect(await screen.findByRole("heading", { name: "Incident desk" })).toBeInTheDocument();
    expect(screen.getByText("8 lines loaded")).toBeInTheDocument();
    expect(screen.getAllByText("Possible SSH credential compromise").length).toBeGreaterThan(0);
  });

  it("shows failed analysis and the deployed login boundary", async () => {
    mockedAuthStatus.mockResolvedValue({
      authenticated: false,
      email: null,
      allowed: false,
      role: null,
      auth_mode: "azure_easy_auth",
      allowlist_enabled: true,
      local_admin: false,
    });
    mockedAnalyzeDemo.mockRejectedValue(new Error("Demo analysis unavailable"));
    render(<App />);

    expect(await screen.findByText("Sign in required")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Login" })).toHaveAttribute(
      "href",
      "/.auth/login/google?post_login_redirect_uri=%2F",
    );
    fireEvent.click(screen.getByRole("button", { name: /^run demo$/i }));

    expect(await screen.findByText("Demo analysis unavailable")).toBeInTheDocument();
  });

  it("hides host controls from analysts while keeping investigation workflows", async () => {
    mockedAuthStatus.mockResolvedValue({
      authenticated: true,
      email: "analyst@example.com",
      allowed: true,
      role: "analyst",
      auth_mode: "azure_easy_auth",
      allowlist_enabled: true,
      local_admin: false,
    });
    render(<App />);

    expect(await screen.findByText("Signed in: analyst@example.com (analyst)")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /live monitor/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^settings$/i })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^run demo$/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Logout" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Login" })).not.toBeInTheDocument();
  });
});
