import { fireEvent, render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import { describe, expect, it, vi } from "vitest";

import { evidenceFixture, findingFixture } from "../../test/workspaceFixtures";
import { EvidencePanel, EvidenceReview } from "./EvidencePanels";

describe("evidence workflow", () => {
  it("renders the exact raw evidence behind a finding", async () => {
    const { container } = render(
      <EvidencePanel finding={findingFixture} evidence={[evidenceFixture]} />,
    );

    expect(screen.getByText(evidenceFixture.raw_text)).toBeInTheDocument();
    expect(screen.getByText(findingFixture.rule_id)).toBeInTheDocument();
    expect(screen.getByText(/t1110.001 password guessing/i)).toBeInTheDocument();
    expect((await axe(container)).violations).toHaveLength(0);
  });

  it("links the evidence workbench back to findings and rules", () => {
    const onSelectFinding = vi.fn();
    const onOpenRule = vi.fn();
    render(
      <EvidenceReview
        findings={[findingFixture]}
        selectedFinding={findingFixture}
        evidence={[evidenceFixture]}
        onSelectFinding={onSelectFinding}
        onOpenRule={onOpenRule}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /ssh brute-force activity/i }));
    expect(onSelectFinding).toHaveBeenCalledWith(findingFixture.id);
    fireEvent.click(screen.getByRole("button", { name: /^rule$/i }));
    expect(onOpenRule).toHaveBeenCalledWith(findingFixture.rule_id);
  });
});
