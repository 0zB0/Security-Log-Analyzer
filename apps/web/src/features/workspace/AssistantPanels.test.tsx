import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { axe } from "vitest-axe";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  explainIncident,
  getAssistantSettings,
  previewAssistantPrompt,
  updateAssistantSettings,
} from "../../lib/api";
import { analysisFixture, incidentFixture } from "../../test/workspaceFixtures";
import { AssistantPanel, SettingsPanel } from "./AssistantPanels";


vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    explainIncident: vi.fn(),
    getAssistantSettings: vi.fn(),
    previewAssistantPrompt: vi.fn(),
    updateAssistantSettings: vi.fn(),
  };
});

const mockedExplain = vi.mocked(explainIncident);
const mockedGetSettings = vi.mocked(getAssistantSettings);
const mockedPreview = vi.mocked(previewAssistantPrompt);
const mockedUpdateSettings = vi.mocked(updateAssistantSettings);
const settings = {
  ai_enabled: true,
  default_model: "qwen3:8b",
  show_prompt_preview: true,
  max_evidence_lines: 20,
  max_evidence_chars: 4000,
};

describe("local assistant controls", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetSettings.mockResolvedValue(settings);
    mockedUpdateSettings.mockImplementation(async (next) => next);
    mockedPreview.mockResolvedValue({
      prompt: "Bounded evidence prompt",
      evidence_line_count: 1,
      truncated: false,
    });
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  it("updates settings, builds the exact prompt, and copies it", async () => {
    const { container } = render(
      <SettingsPanel result={analysisFixture} selectedIncident={incidentFixture} />,
    );

    expect(await screen.findByRole("heading", { name: "Local AI settings" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: /local ai enabled/i }));
    await waitFor(() =>
      expect(mockedUpdateSettings).toHaveBeenCalledWith(
        expect.objectContaining({ ai_enabled: false }),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: /build preview/i }));
    expect(await screen.findByText("Bounded evidence prompt")).toBeInTheDocument();
    expect(mockedPreview).toHaveBeenCalledWith(
      expect.objectContaining({
        incident: incidentFixture,
        findings: analysisFixture.findings,
        evidence: analysisFixture.evidence,
      }),
    );

    fireEvent.click(screen.getByRole("button", { name: /copy prompt/i }));
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith("Bounded evidence prompt"),
    );
    expect((await axe(container)).violations).toHaveLength(0);
  });

  it("renders settings load failures instead of an endless loading state", async () => {
    mockedGetSettings.mockRejectedValue(new Error("Settings API unavailable"));
    render(<SettingsPanel result={null} selectedIncident={null} />);

    expect(await screen.findByText("Settings API unavailable")).toBeInTheDocument();
    expect(screen.queryByText("Loading settings.")).not.toBeInTheDocument();
  });

  it("generates evidence-bounded output and clears stale output on failure", async () => {
    mockedExplain
      .mockResolvedValueOnce({
        provider: "ollama",
        model: "qwen3:8b",
        mode: "local",
        prompt: "Bounded evidence prompt",
        summary: "Review the source IP.",
        key_points: ["Repeated failures"],
        recommended_next_steps: ["Validate the account"],
        evidence_references: [7],
        guardrails: ["Verify raw evidence"],
      })
      .mockRejectedValueOnce(new Error("Local model offline"));
    const onResponse = vi.fn();
    const { rerender } = render(
      <AssistantPanel
        result={analysisFixture}
        selectedIncident={incidentFixture}
        response={null}
        status={{
          enabled: true,
          provider: "ollama",
          url: "http://127.0.0.1:11434",
          model: "qwen3:8b",
          available: true,
          installed_models: ["qwen3:8b"],
          error: null,
        }}
        onResponse={onResponse}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /generate explanation/i }));
    await waitFor(() => expect(onResponse).toHaveBeenCalledWith(expect.objectContaining({ model: "qwen3:8b" })));

    rerender(
      <AssistantPanel
        result={analysisFixture}
        selectedIncident={incidentFixture}
        response={null}
        status={{
          enabled: true,
          provider: "ollama",
          url: "http://127.0.0.1:11434",
          model: "qwen3:8b",
          available: true,
          installed_models: ["qwen3:8b"],
          error: null,
        }}
        onResponse={onResponse}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /generate explanation/i }));
    expect(await screen.findByText("Local model offline")).toBeInTheDocument();
    expect(onResponse).toHaveBeenLastCalledWith(null);
  });
});
