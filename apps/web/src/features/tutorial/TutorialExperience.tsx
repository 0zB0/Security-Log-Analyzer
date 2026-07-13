import { useEffect, useRef, useState } from "react";
import { HelpCircle, PlayCircle, X } from "lucide-react";

import type { WorkspaceView } from "../../app/workspaceTypes";
import {
  COMMON_TUTORIAL_CONTROLS,
  TUTORIAL_SECTIONS,
  tutorialSection,
  type PublicTutorialView,
  type TutorialControl,
} from "./tutorialRegistry";
import tutorialVideoManifest from "../../../public/tutorial-videos/manifest.json";

export function ContextHelpButton({
  view,
  onStart,
}: {
  view: WorkspaceView;
  onStart: (view: PublicTutorialView) => void;
}) {
  const section = tutorialSection(view);
  return (
    <button
      className="context-help-button"
      type="button"
      aria-label={`Start ${section.title} guided tour`}
      title={`Explain ${section.title}`}
      data-tour="context-help"
      onClick={() => onStart(section.view)}
    >
      <HelpCircle size={18} aria-hidden="true" />
    </button>
  );
}

export function TutorialPage({
  onStart,
}: {
  onStart: (view: PublicTutorialView) => void;
}) {
  const [activeVideoView, setActiveVideoView] = useState<PublicTutorialView | null>(null);

  return (
    <section className="tutorial-page" aria-labelledby="tutorial-heading">
      <div className="tutorial-intro surface">
        <h2 id="tutorial-heading">TraceHawk guided tutorial</h2>
        <p>
          Use this as an evidence-first learning tool. Every view is a separate chapter explaining
          why the view exists, exactly what it shows, how to interpret a worked example, and what
          every visible control does when used.
        </p>
        <nav className="tutorial-chapter-links" aria-label="Tutorial chapters">
          {TUTORIAL_SECTIONS.map((section, index) => (
            <a href={`#tutorial-${section.view}`} key={section.view}>
              {String(index + 1).padStart(2, "0")} {section.title}
            </a>
          ))}
        </nav>
      </div>

      <section className="surface tutorial-common-controls" aria-labelledby="common-controls-heading">
        <div className="tutorial-card-heading">
          <span>00</span>
          <div>
            <h3 id="common-controls-heading">Controls visible across the workspace</h3>
            <p>
              These navigation, intake, privacy, and help controls keep the same meaning on every
              public-demo view. View-specific controls are documented inside each chapter below.
            </p>
          </div>
        </div>
        <ControlReference controls={COMMON_TUTORIAL_CONTROLS} />
      </section>

      <div className="tutorial-section-grid">
        {TUTORIAL_SECTIONS.map((section, index) => {
          const video = tutorialVideoManifest.find((item) => item.view === section.view);
          const isVideoOpen = activeVideoView === section.view;
          return (
          <article
            className="surface tutorial-section-card"
            id={`tutorial-${section.view}`}
            key={section.view}
          >
            <div className="tutorial-card-heading">
              <span>{String(index + 1).padStart(2, "0")}</span>
              <div>
                <h3>{section.title}</h3>
                <p>{section.purpose}</p>
              </div>
            </div>

            <div className="tutorial-learning-grid">
              <section className="tutorial-learning-block" aria-labelledby={`${section.view}-shows`}>
                <h4 id={`${section.view}-shows`}>{section.title}: What this view shows</h4>
                <div className="tutorial-display-list">
                  {section.whatItShows.map((item) => (
                    <article key={item.label}>
                      <h5>{item.label}</h5>
                      <p>{item.explanation}</p>
                      <p className="tutorial-example-line">
                        <strong>Example:</strong> {item.example}
                      </p>
                    </article>
                  ))}
                </div>
              </section>

              <section className="tutorial-learning-block" aria-labelledby={`${section.view}-example`}>
                <h4 id={`${section.view}-example`}>
                  {section.title}: Worked interpretation example
                </h4>
                <dl className="tutorial-example-grid">
                  <dt>Scenario</dt>
                  <dd>{section.example.scenario}</dd>
                  <dt>What you see</dt>
                  <dd>{section.example.observation}</dd>
                  <dt>What it means</dt>
                  <dd>{section.example.interpretation}</dd>
                  <dt>Next step</dt>
                  <dd>{section.example.nextStep}</dd>
                </dl>
              </section>
            </div>

            <section className="tutorial-learning-block" aria-labelledby={`${section.view}-controls`}>
              <h4 id={`${section.view}-controls`}>
                {section.title}: Buttons and controls on this view
              </h4>
              <ControlReference controls={section.controls} />
            </section>

            <section className="tutorial-boundaries" aria-label={`${section.title} learning boundaries`}>
              <div>
                <strong>Data origin</strong>
                <p>{section.dataOrigin}</p>
              </div>
              <div>
                <strong>How to read it</strong>
                <p>{section.readingMethod}</p>
              </div>
              <div>
                <strong>Limitation</strong>
                <p>{section.limitation}</p>
              </div>
            </section>

            {video ? (
              <section
                className="tutorial-video-reference"
                aria-labelledby={`${section.view}-video-heading`}
                data-tour={`tutorial-video-${section.view}`}
              >
                <div className="tutorial-video-copy">
                  <PlayCircle size={22} aria-hidden="true" />
                  <div>
                    <h4 id={`${section.view}-video-heading`}>Narrated video: {video.title}</h4>
                    <p>{video.description}</p>
                    <span>
                      English male narration · {formatVideoDuration(video.duration_seconds)} ·
                      English captions
                    </span>
                  </div>
                </div>
                <button
                  className="upload-button"
                  type="button"
                  aria-expanded={isVideoOpen}
                  aria-controls={`${section.view}-video-player`}
                  onClick={() => setActiveVideoView(isVideoOpen ? null : section.view)}
                >
                  {isVideoOpen ? `Close ${section.title} video` : `Watch ${section.title} narrated video`}
                </button>
                {isVideoOpen ? (
                  <div className="tutorial-video-player" id={`${section.view}-video-player`}>
                    <video
                      controls
                      playsInline
                      preload="metadata"
                      aria-label={`${section.title} narrated tutorial video`}
                    >
                      <source src={video.video} type="video/mp4" />
                      <track
                        default
                        kind="captions"
                        src={video.captions}
                        srcLang={video.language}
                        label="English"
                      />
                      Your browser does not support the tutorial video player.
                    </video>
                    <p>
                      The recording uses only TraceHawk's sanitized SSH sample. It contains no
                      visitor uploads and does not transmit playback data to an external service.
                    </p>
                  </div>
                ) : null}
              </section>
            ) : null}

            <div className="tutorial-chapter-actions">
              <button
                className="upload-button"
                type="button"
                onClick={() => onStart(section.view)}
              >
                Start {section.title} guided walkthrough
              </button>
              <a href="#tutorial-heading">Back to chapter index</a>
            </div>
          </article>
          );
        })}
      </div>
    </section>
  );
}

function formatVideoDuration(durationSeconds: number): string {
  const rounded = Math.round(durationSeconds);
  return `${Math.floor(rounded / 60)}:${String(rounded % 60).padStart(2, "0")}`;
}

function ControlReference({ controls }: { controls: TutorialControl[] }) {
  return (
    <div className="tutorial-control-list">
      {controls.map((control) => (
        <article className="tutorial-control-item" key={control.label}>
          <div className="tutorial-control-name">
            <strong>{control.label}</strong>
            <span>{control.kind}</span>
          </div>
          <div>
            <span>When used</span>
            <p>{control.action}</p>
          </div>
          <div>
            <span>Result</span>
            <p>{control.result}</p>
          </div>
        </article>
      ))}
    </div>
  );
}

export function GuidedTour({
  initialView,
  onNavigate,
  onClose,
}: {
  initialView: PublicTutorialView;
  onNavigate: (view: PublicTutorialView) => void;
  onClose: () => void;
}) {
  const section = tutorialSection(initialView);
  const [stepIndex, setStepIndex] = useState(0);
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const step = section.steps[stepIndex];

  useEffect(() => {
    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    return () => previousFocusRef.current?.focus();
  }, []);

  useEffect(() => {
    onNavigate(section.view);
    let target: Element | null = null;
    const frame = window.requestAnimationFrame(() => {
      target = document.querySelector(step.target);
      target?.classList.add("tour-target-active");
      if (target instanceof HTMLElement) {
        target.scrollIntoView?.({ block: "center", behavior: "smooth" });
      }
      dialogRef.current?.focus();
    });
    return () => {
      window.cancelAnimationFrame(frame);
      target?.classList.remove("tour-target-active");
    };
  }, [onNavigate, section.view, step.target]);

  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        onClose();
      }
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  const isLast = stepIndex === section.steps.length - 1;
  return (
    <div className="guided-tour-layer">
      <div
        className="guided-tour-dialog"
        role="dialog"
        aria-modal="false"
        aria-labelledby="guided-tour-title"
        aria-describedby="guided-tour-body"
        ref={dialogRef}
        tabIndex={-1}
      >
        <div className="guided-tour-topline">
          <span aria-live="polite">
            {section.title}: {stepIndex + 1} / {section.steps.length}
          </span>
          <button type="button" aria-label="Close guided tour" onClick={onClose}>
            <X size={17} aria-hidden="true" />
          </button>
        </div>
        <h2 id="guided-tour-title">{step.title}</h2>
        <p id="guided-tour-body">{step.body}</p>
        <div className="guided-tour-actions">
          <button
            type="button"
            className="stop-button"
            disabled={stepIndex === 0}
            onClick={() => setStepIndex((current) => Math.max(0, current - 1))}
          >
            Back
          </button>
          <button type="button" className="stop-button" onClick={() => setStepIndex(0)}>
            Restart
          </button>
          <button type="button" className="stop-button" onClick={onClose}>
            Skip tour
          </button>
          <button
            type="button"
            className="upload-button"
            onClick={() => {
              if (isLast) {
                onClose();
              } else {
                setStepIndex((current) => current + 1);
              }
            }}
          >
            {isLast ? "Finish" : "Next"}
          </button>
        </div>
      </div>
    </div>
  );
}
