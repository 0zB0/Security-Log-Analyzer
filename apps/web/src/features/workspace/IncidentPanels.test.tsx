import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { axe } from "vitest-axe";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createIncidentNote, listIncidentNotes } from "../../lib/api";
import { findingFixture, incidentFixture } from "../../test/workspaceFixtures";
import { IncidentDetail, IncidentOverview } from "./IncidentPanels";

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    createIncidentNote: vi.fn(),
    listIncidentNotes: vi.fn(),
  };
});

const mockedListNotes = vi.mocked(listIncidentNotes);
const mockedCreateNote = vi.mocked(createIncidentNote);

describe("incident workflow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedListNotes.mockResolvedValue([]);
  });

  it("selects an incident from the analyst overview", async () => {
    const onSelect = vi.fn();
    const { container } = render(
      <IncidentOverview
        incidents={[incidentFixture]}
        selectedIncident={null}
        onSelectIncident={onSelect}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /possible ssh credential compromise/i }));

    expect(onSelect).toHaveBeenCalledWith(incidentFixture);
    expect((await axe(container)).violations).toHaveLength(0);
  });

  it("loads notes, records an analyst decision, and opens linked evidence", async () => {
    mockedCreateNote.mockResolvedValue({
      id: "note-1",
      analysis_id: "analysis-1",
      incident_id: incidentFixture.id,
      body: "Escalate this incident.",
      note_type: "decision",
      author: "analyst",
      created_at: "2026-01-01T00:03:00Z",
      updated_at: "2026-01-01T00:03:00Z",
    });
    const onSelectFinding = vi.fn();
    render(
      <IncidentDetail
        analysisId="analysis-1"
        incident={incidentFixture}
        findings={[findingFixture]}
        onSelectFinding={onSelectFinding}
      />,
    );

    await waitFor(() => expect(mockedListNotes).toHaveBeenCalledWith("analysis-1", incidentFixture.id));
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "decision" } });
    fireEvent.change(screen.getByPlaceholderText(/record the analyst decision/i), {
      target: { value: "Escalate this incident." },
    });
    fireEvent.click(screen.getByRole("button", { name: /save note/i }));

    await screen.findByText("Escalate this incident.");
    expect(mockedCreateNote).toHaveBeenCalledWith(
      expect.objectContaining({ note_type: "decision", incident_id: incidentFixture.id }),
    );

    fireEvent.click(screen.getByRole("button", { name: /ssh brute-force activity/i }));
    expect(onSelectFinding).toHaveBeenCalledWith(findingFixture.id);
  });
});
