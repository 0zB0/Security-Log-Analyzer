import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { axe } from "vitest-axe";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  analyzeCaseBundle,
  analyzeDemo,
  analyzeRealLabCase,
  analyzeSample,
  analyzeUpload,
  analyzePublicDemo,
  analyzePublicSample,
  getAssistantStatus,
  getAuthStatus,
  getPublicDemoStatus,
  listIncidentNotes,
} from "../lib/api";
import { analysisFixture } from "../test/workspaceFixtures";
import { App } from "./main";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    analyzeCaseBundle: vi.fn(),
    analyzeDemo: vi.fn(),
    analyzeRealLabCase: vi.fn(),
    analyzeSample: vi.fn(),
    analyzeUpload: vi.fn(),
    analyzePublicDemo: vi.fn(),
    analyzePublicSample: vi.fn(),
    getAssistantStatus: vi.fn(),
    getAuthStatus: vi.fn(),
    getPublicDemoStatus: vi.fn(),
    listIncidentNotes: vi.fn(),
  };
});

const mockedAnalyzeDemo = vi.mocked(analyzeDemo);
const mockedAnalyzeCaseBundle = vi.mocked(analyzeCaseBundle);
const mockedAnalyzeRealLabCase = vi.mocked(analyzeRealLabCase);
const mockedAnalyzeSample = vi.mocked(analyzeSample);
const mockedAnalyzeUpload = vi.mocked(analyzeUpload);
const mockedAnalyzePublicDemo = vi.mocked(analyzePublicDemo);
const mockedAnalyzePublicSample = vi.mocked(analyzePublicSample);
const mockedAssistantStatus = vi.mocked(getAssistantStatus);
const mockedAuthStatus = vi.mocked(getAuthStatus);
const mockedPublicDemoStatus = vi.mocked(getPublicDemoStatus);
const mockedListNotes = vi.mocked(listIncidentNotes);

describe("application investigation workflow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.history.replaceState({}, "", "/");
    mockedPublicDemoStatus.mockResolvedValue({
      enabled: false,
      profile: "private",
      storage: "disabled",
      external_ai: false,
      max_bytes: 524288,
      max_lines: 20000,
      session_timeout_seconds: 1800,
      allowed_extensions: [".csv", ".json", ".jsonl", ".log", ".txt"],
      available_views: [],
    });
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
    mockedAnalyzeCaseBundle.mockResolvedValue(analysisFixture);
    mockedAnalyzeRealLabCase.mockResolvedValue(analysisFixture);
    mockedAnalyzeSample.mockResolvedValue(analysisFixture);
    mockedAnalyzeUpload.mockResolvedValue(analysisFixture);
    mockedAnalyzePublicDemo.mockResolvedValue({
      analysis: analysisFixture,
      ephemeral: true,
      stored: false,
      external_ai: false,
      lifecycle: "request_and_browser_memory_only",
      session_timeout_seconds: 1800,
    });
    mockedAnalyzePublicSample.mockResolvedValue({
      analysis: analysisFixture,
      ephemeral: true,
      stored: false,
      external_ai: false,
      lifecycle: "request_and_browser_memory_only",
      session_timeout_seconds: 1800,
    });
  });

  it("runs the demo and moves from empty intake to an evidence-backed incident", async () => {
    mockedAnalyzeDemo.mockResolvedValue(analysisFixture);
    render(<App />);

    expect((await screen.findAllByText("No file selected")).length).toBeGreaterThan(0);
    fireEvent.click(await screen.findByRole("button", { name: /^run demo$/i }));

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
    fireEvent.click(await screen.findByRole("button", { name: /^run demo$/i }));

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

  it("supports keyboard search focus and clears it with Escape", async () => {
    const { container } = render(<App />);
    await screen.findByText("Local admin mode");
    const search = screen.getByRole("textbox", { name: "Global investigation search" });

    fireEvent.keyDown(window, { key: "/" });
    expect(search).toHaveFocus();
    fireEvent.change(search, { target: { value: "198.51.100.10" } });
    expect(search).toHaveValue("198.51.100.10");
    fireEvent.keyDown(window, { key: "Escape" });
    expect(search).toHaveValue("");
    expect(search).not.toHaveFocus();
    expect((await axe(container)).violations).toHaveLength(0);
  });

  it("recovers from a rejected analysis action without reloading the workspace", async () => {
    mockedAnalyzeDemo
      .mockRejectedValueOnce(new Error("Demo rejected by policy"))
      .mockResolvedValueOnce(analysisFixture);
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: /^run demo$/i }));
    expect(await screen.findByText("Demo rejected by policy")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /^run demo$/i }));

    expect(await screen.findByRole("heading", { name: "Incident desk" })).toBeInTheDocument();
    expect(screen.queryByText("Demo rejected by policy")).not.toBeInTheDocument();
  });

  it("executes sample, real-lab, single-file, and case-bundle intake paths", async () => {
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: /^run sample$/i }));
    await waitFor(() => expect(mockedAnalyzeSample).toHaveBeenCalledOnce());

    fireEvent.click(screen.getByRole("button", { name: /^real lab case$/i }));
    await waitFor(() => expect(mockedAnalyzeRealLabCase).toHaveBeenCalledOnce());
    expect(screen.getByRole("heading", { name: "Case investigation" })).toBeInTheDocument();

    const file = new File(["event"], "event.log", { type: "text/plain" });
    fireEvent.change(screen.getByLabelText("Browse..."), { target: { files: [file] } });
    await waitFor(() => expect(mockedAnalyzeUpload).toHaveBeenCalledWith(file));

    fireEvent.change(screen.getByLabelText("Case..."), { target: { files: [file, file] } });
    await waitFor(() => expect(mockedAnalyzeCaseBundle).toHaveBeenCalled());
    expect(screen.getByRole("heading", { name: "Case investigation" })).toBeInTheDocument();
  });

  it("runs a session-only public analysis and hides private capabilities", async () => {
    mockedPublicDemoStatus.mockResolvedValue({
      enabled: true,
      profile: "public_demo",
      storage: "disabled",
      external_ai: false,
      max_bytes: 524288,
      max_lines: 20000,
      session_timeout_seconds: 1800,
      allowed_extensions: [".csv", ".json", ".jsonl", ".log", ".txt"],
      available_views: ["upload", "incidents", "findings", "evidence", "tutorial"],
    });
    render(<App />);

    expect(await screen.findByText("Public session-only demo")).toBeInTheDocument();
    expect(screen.getByText("Session-only processing")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^case$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /local ai/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /live monitor/i })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^findings$/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^tutorial$/i })).toBeInTheDocument();

    const file = new File(["event"], "event.log", { type: "text/plain" });
    fireEvent.change(screen.getByLabelText("Browse..."), { target: { files: [file] } });
    await waitFor(() => expect(mockedAnalyzePublicDemo).toHaveBeenCalledWith(file));
    expect(await screen.findByRole("heading", { name: "Incident desk" })).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("button", { name: "Clear session" })[0]);
    expect(screen.getAllByText("No file selected").length).toBeGreaterThan(0);
  });

  it("fails closed while the runtime profile is unresolved", () => {
    mockedPublicDemoStatus.mockReturnValue(new Promise(() => undefined));

    render(<App />);

    expect(screen.getByRole("heading", { name: "Loading TraceHawk" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^case$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /local ai/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Browse...")).not.toBeInTheDocument();
  });

  it("rejects an oversized public file before reading or sending it", async () => {
    mockedPublicDemoStatus.mockResolvedValue({
      enabled: true,
      profile: "public_demo",
      storage: "disabled",
      external_ai: false,
      max_bytes: 4,
      max_lines: 20,
      session_timeout_seconds: 1800,
      allowed_extensions: [".log"],
      available_views: ["upload"],
    });
    render(<App />);

    const file = new File(["12345"], "event.log", { type: "text/plain" });
    fireEvent.change(await screen.findByLabelText("Browse..."), {
      target: { files: [file] },
    });

    expect(await screen.findByText("Public demo files are limited to 4 bytes.")).toBeInTheDocument();
    expect(mockedAnalyzePublicDemo).not.toHaveBeenCalled();
  });

  it("clears public evidence when the inactivity deadline expires", async () => {
    vi.useFakeTimers();
    try {
      mockedPublicDemoStatus.mockResolvedValue({
        enabled: true,
        profile: "public_demo",
        storage: "disabled",
        external_ai: false,
        max_bytes: 524288,
        max_lines: 20000,
        session_timeout_seconds: 1,
        allowed_extensions: [".log"],
        available_views: ["upload", "incidents"],
      });
      render(<App />);
      await act(async () => {
        await Promise.resolve();
      });

      fireEvent.click(screen.getByRole("button", { name: /^run demo$/i }));
      await act(async () => {
        await Promise.resolve();
      });
      expect(screen.getByRole("heading", { name: "Incident desk" })).toBeInTheDocument();

      act(() => vi.advanceTimersByTime(1000));

      expect(screen.getAllByText("No file selected").length).toBeGreaterThan(0);
      expect(screen.getByRole("heading", { name: "Investigation workspace" })).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});
