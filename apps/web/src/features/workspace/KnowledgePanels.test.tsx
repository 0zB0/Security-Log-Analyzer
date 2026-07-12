import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";

import { getRuleLibrary } from "../../lib/api";
import { analysisFixture } from "../../test/workspaceFixtures";
import { DetectionLibrary } from "./KnowledgePanels";


vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return { ...actual, getRuleLibrary: vi.fn() };
});


const mockedRuleLibrary = vi.mocked(getRuleLibrary);


it("moves rule detail to a current-case match when Found only is enabled", async () => {
  mockedRuleLibrary.mockResolvedValue({
    rule_count: 2,
    categories: ["Auth", "Web"],
    rules: [
      {
        id: "not-found-rule",
        title: "Unrelated rule",
        category: "Web",
        description: "Not present in this case.",
        danger_summary: "Unrelated danger.",
        severity: "medium",
        confidence: "medium",
        log_types: ["web_access"],
        mitre_tactic: null,
        mitre_technique_id: null,
        mitre_technique_name: null,
        look_for: [],
        false_positives: [],
        recommendations: [],
        correlation: {
          family: null,
          incident_title: null,
          behaviors: [],
          entity_fields: ["source_ip", "username", "host"],
          max_gap_minutes: 60,
          intrinsic_sequence_score: 0,
          intrinsic_sequence_rationale: null,
          intrinsic_sequence_summary: null,
        },
      },
      {
        id: "ssh-bruteforce-001",
        title: "SSH brute force attempt",
        category: "Auth",
        description: "Present in this case.",
        danger_summary: "Credential access risk.",
        severity: "high",
        confidence: "high",
        log_types: ["linux_auth"],
        mitre_tactic: "Credential Access",
        mitre_technique_id: "T1110.001",
        mitre_technique_name: "Password Guessing",
        look_for: ["Repeated failures"],
        false_positives: [],
        recommendations: ["Validate the source"],
        correlation: {
          family: "ssh_auth",
          incident_title: null,
          behaviors: ["ssh_failures"],
          entity_fields: ["source_ip", "username", "host"],
          max_gap_minutes: 30,
          intrinsic_sequence_score: 0,
          intrinsic_sequence_rationale: null,
          intrinsic_sequence_summary: null,
        },
      },
    ],
  });

  render(
    <DetectionLibrary
      result={analysisFixture}
      selectedRuleId={null}
      onSelectRule={vi.fn()}
    />,
  );

  expect(await screen.findByRole("heading", { name: "Unrelated rule" })).toBeInTheDocument();
  fireEvent.change(screen.getByRole("combobox", { name: "Detection category" }), {
    target: { value: "Auth" },
  });
  expect(screen.getByRole("heading", { name: "SSH brute force attempt" })).toBeInTheDocument();

  fireEvent.change(screen.getByRole("textbox", { name: "Search detection rules" }), {
    target: { value: "no-such-technique" },
  });
  expect(screen.getByText("0 visible rules from the deterministic rule engine.")).toBeInTheDocument();
  expect(screen.getByText("No rule selected.")).toBeInTheDocument();

  fireEvent.change(screen.getByRole("textbox", { name: "Search detection rules" }), {
    target: { value: "" },
  });
  fireEvent.change(screen.getByRole("combobox", { name: "Detection category" }), {
    target: { value: "all" },
  });
  fireEvent.click(screen.getByRole("checkbox", { name: "Found only" }));

  await waitFor(() => {
    expect(screen.getByRole("heading", { name: "SSH brute force attempt" })).toBeInTheDocument();
  });
  expect(screen.getByText("Current case")).toBeInTheDocument();
  expect(screen.getByText("Detected")).toBeInTheDocument();
});
