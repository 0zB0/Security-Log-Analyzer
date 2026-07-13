import { fireEvent, render, screen } from "@testing-library/react";
import { axe } from "vitest-axe";
import { describe, expect, it, vi } from "vitest";

import { GuidedTour, TutorialPage } from "./TutorialExperience";
import { COMMON_TUTORIAL_CONTROLS, TUTORIAL_SECTIONS } from "./tutorialRegistry";


describe("public guided tutorial", () => {
  it("uses one complete registry for the tutorial page", async () => {
    const onStart = vi.fn();
    const { container } = render(<TutorialPage onStart={onStart} />);

    expect(TUTORIAL_SECTIONS.map((section) => section.view)).toEqual([
      "upload",
      "incidents",
      "findings",
      "evidence",
      "entities",
      "mitre",
      "reports",
      "library",
    ]);
    for (const section of TUTORIAL_SECTIONS) {
      expect(screen.getByRole("heading", { name: section.title })).toBeInTheDocument();
      expect(section.whatItShows.length).toBeGreaterThanOrEqual(2);
      expect(section.controls.length).toBeGreaterThanOrEqual(1);
      expect(section.steps.length).toBeGreaterThanOrEqual(3);
      expect(section.example.scenario).not.toHaveLength(0);
      expect(section.example.interpretation).not.toHaveLength(0);
      expect(section.example.nextStep).not.toHaveLength(0);
    }
    expect(COMMON_TUTORIAL_CONTROLS.map((control) => control.label)).toEqual(
      expect.arrayContaining([
        "Upload",
        "Entities",
        "MITRE",
        "Incidents",
        "Findings",
        "Evidence",
        "Reports",
        "Library",
        "Tutorial",
        "Global investigation search",
        "Clear session — top bar",
        "Browse…",
        "Run demo",
        "Run sample",
        "Markdown — intake shortcut",
        "Question-mark help",
      ]),
    );
    for (const section of TUTORIAL_SECTIONS) {
      expect(
        screen.getByRole("heading", { name: `${section.title}: What this view shows` }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("heading", {
          name: `${section.title}: Worked interpretation example`,
        }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("heading", {
          name: `${section.title}: Buttons and controls on this view`,
        }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: `Watch ${section.title} narrated video` }),
      ).toBeInTheDocument();
    }
    expect(document.querySelectorAll("video")).toHaveLength(0);
    expect(screen.getByText("Controls visible across the workspace")).toBeInTheDocument();
    expect(screen.getByText("SSH brute force attempt can be high severity, high confidence, ten events, and T1110.001.")).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Start Evidence guided walkthrough" }),
    );
    expect(onStart).toHaveBeenCalledWith("evidence");
    fireEvent.click(
      screen.getByRole("button", { name: "Watch Evidence narrated video" }),
    );
    const video = screen.getByLabelText("Evidence narrated tutorial video");
    expect(video).toBeInTheDocument();
    expect(video.querySelector("source")).toHaveAttribute(
      "src",
      "/tutorial-videos/evidence.mp4",
    );
    expect(video.querySelector("track")).toHaveAttribute(
      "src",
      "/tutorial-videos/evidence.en.vtt",
    );
    fireEvent.click(screen.getByRole("button", { name: "Close Evidence video" }));
    expect(screen.queryByLabelText("Evidence narrated tutorial video")).not.toBeInTheDocument();
    expect((await axe(container)).violations).toHaveLength(0);
  });

  it("supports next, back, restart, finish, and Escape", () => {
    const onNavigate = vi.fn();
    const onClose = vi.fn();
    render(
      <>
        <button data-tour="nav-evidence">Evidence target</button>
        <div data-tour="evidence-findings">Finding controls</div>
        <div data-tour="evidence-raw">Evidence content</div>
        <div data-tour="evidence-metadata">Evidence metadata</div>
        <GuidedTour initialView="evidence" onNavigate={onNavigate} onClose={onClose} />
      </>,
    );

    expect(screen.getByText("Evidence: 1 / 4")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Back" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Evidence: 2 / 4")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Evidence: 3 / 4")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Evidence: 4 / 4")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Finish" }));
    expect(onClose).toHaveBeenCalledOnce();
    onClose.mockClear();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByText("Evidence: 3 / 4")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Restart" }));
    expect(screen.getByText("Evidence: 1 / 4")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Skip tour" }));
    expect(onClose).toHaveBeenCalledOnce();
    onClose.mockClear();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onNavigate).toHaveBeenCalledWith("evidence");
    expect(onClose).toHaveBeenCalledOnce();
  });
});
