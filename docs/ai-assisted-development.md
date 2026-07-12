# AI-Assisted Development Disclosure

TraceHawk was developed with extensive assistance from generative AI coding tools. The maintainer
estimates that approximately 99% of the implementation code was initially generated or drafted by
AI. This is an honest estimate rather than a line-by-line measurement.

## Tools, Models, And Extent Of Use

The model labels below are the labels shown in the development environment. Reasoning settings
describe how the models were run; they are not separate authors or project contributors.

| Tool or model | Setting | Project phase | Extent and purpose |
| --- | --- | --- | --- |
| GPT-5.5 | Medium and high reasoning | Majority of the project | Product ideation, requirements, architecture, threat boundaries, backend and frontend code, tests, fixtures, debugging, documentation, and deployment workflows |
| GPT-5.6 | High reasoning | Later development after the model became available | Further implementation, review, test expansion, hardening, documentation, and evaluation of project limitations |

AI assistance was substantive rather than limited to autocomplete or grammar correction. It
affected the following parts of the development lifecycle:

- exploring and refining the original product idea;
- decomposing the work and proposing architecture and security boundaries;
- drafting and iterating on backend and frontend implementation;
- generating and revising tests, fixtures, negative controls, and verification workflows;
- investigating failures and proposing fixes;
- drafting and editing technical documentation, reports, and deployment evidence.

The change of model did not change the project's evidence-first principle or the requirement that
generated changes be understood and verified before acceptance.

The approximately 99% estimate refers to implementation code that began as AI-generated or
AI-drafted output. It does not mean that 99% of the engineering judgment, validation, or
responsibility was delegated. Complete prompt and response histories were not preserved in this
repository, so the estimate is transparent but not independently auditable line by line.

## Human Responsibility

AI assistance does not transfer authorship responsibility to a tool. The maintainer remains
responsible for the project and has:

- defined the product direction, scope, and evidence-first security boundaries;
- selected and reviewed the architecture and implementation approach;
- inspected, tested, debugged, and iterated on generated changes;
- verified deterministic detections against positive and negative scenarios;
- reviewed how parsing, detection, correlation, persistence, reporting, authentication, and
  deployment fit together;
- retained only changes that could be explained and defended, including why they are present and
  what their limitations are.

The maintainer understands the system's operating principles, test strategy, major implementation
decisions, and known limitations. AI-generated output is treated as an untrusted draft that requires
human review, not as evidence that a feature is correct or secure.

The AI systems are not listed as authors and cannot approve changes, accept accountability, or
attest that the work is original, correct, or secure. Those responsibilities remain with the human
maintainer.

## Verification Standard

Project claims should be evaluated from executable evidence rather than from who typed the code.
The repository therefore includes deterministic tests, labeled detection scenarios, benign negative
controls, external dataset evaluation, performance checks, security scans, deployment verification,
and reproducible proof artifacts.

These controls reduce risk but do not eliminate it. Passing tests cannot prove production readiness,
complete detection coverage, or the absence of security defects. The documented limitations and the
external detection results remain part of the assessment.

Generated factual claims, links, and citations require source verification before acceptance. No
production logs, client data, credentials, API tokens, private keys, or other intentionally
confidential evidence should be supplied to an AI tool as part of this project's development.

## Academic Use

This disclosure does not override the rules of a university, faculty, course, supervisor, or
assessment. If the project is submitted for academic credit, the applicable AI policy must be
checked in advance and any additional declaration, prompt log, appendix, or oral demonstration must
also be provided. A reviewer should be able to ask the maintainer to explain, test, or modify any
material part of the submitted system.

## How To Assess This Project

For academic or portfolio review, the intended contribution is not a claim of manually typing every
line. It is the ability to:

1. explain the problem and the chosen product boundaries;
2. trace findings back to deterministic rules and raw evidence;
3. explain and modify the architecture without relying on opaque AI behavior;
4. design meaningful tests and interpret their failures;
5. identify where the system is reliable, where it is heuristic, and what would be required for
   production use.

This disclosure is provided so reviewers can judge the project, the engineering process, and the
maintainer's understanding on accurate terms.

## Reference Practices

This disclosure follows the common elements found in current academic and software contribution
guidance: identify the tool and version, state the purpose and extent of use, document human review,
and retain human accountability.

- [ACM policy guidance on generative AI and disclosure](https://www.acm.org/publications/policies/frequently-asked-questions)
- [IEEE guidance for disclosure of AI-generated content](https://open.ieee.org/author-guidelines-for-artificial-intelligence-ai-generated-text/)
- [Oxford Academic AI Disclosure Statement template](https://academic.oup.com/dsh/pages/General_Instructions)
- [EHU template for declaring generative AI use](https://www.ehu.eus/en/web/adimen-artifiziala/c%C3%B3mo-declarar-el-uso-de-la-ia-generativa)
- [University of Geneva declaration templates](https://www.unige.ch/sciences/en/lafaculte/directive-generative-artificial-intelligence/templates-declaring-use-generative-artificial-intelligence)
- [Coder AI contribution guidelines](https://coder.com/docs/about/contributing/AI_CONTRIBUTING)
