# TraceHawk Test Tools

Local smoke tools for validating scenario, live, report, UI, Ollama, and Azure-public behavior.

Run from the repository root through `make` targets.

Documentation gates:

- `check_markdown_links.py` rejects missing or repository-escaping local Markdown links;
- `check_docs_structure.py` enforces hub coverage, canonical sections, one H1 per canonical guide,
  and private-marker/TODO checks for the main technical documentation;
- `make docs-check` runs both gates.
