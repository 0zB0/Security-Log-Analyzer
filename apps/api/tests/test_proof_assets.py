import hashlib
import json
from pathlib import Path

from PIL import Image
from pypdf import PdfReader


ROOT = Path(__file__).resolve().parents[3]


def test_release_visual_assets_are_complete_and_readable() -> None:
    expected = [
        ROOT / "docs/assets/demo/01-upload-analysis.png",
        ROOT / "docs/assets/demo/02-incident-correlation.png",
        ROOT / "docs/assets/demo/03-report-export.png",
        ROOT / "docs/assets/demo/04-case-correlation.png",
    ]
    for path in expected:
        with Image.open(path) as image:
            assert image.format == "PNG"
            assert image.width >= 1200
            assert image.height >= 700

    with Image.open(ROOT / "docs/assets/demo/tracehawk-demo.gif") as demo:
        assert demo.format == "GIF"
        assert demo.n_frames == 16
        assert demo.size == (1280, 720)
        total_duration = 0
        for frame_index in range(demo.n_frames):
            demo.seek(frame_index)
            total_duration += int(demo.info.get("duration", 0))
        assert 5_000 <= total_duration <= 8_000


def test_sample_report_artifacts_are_readable() -> None:
    html_path = ROOT / "docs/assets/reports/tracehawk-sample-incident.html"
    pdf_path = ROOT / "docs/assets/reports/tracehawk-sample-incident.pdf"
    html = html_path.read_text(encoding="utf-8")
    reader = PdfReader(pdf_path)
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert html.startswith("<!doctype html>")
    assert "Correlated security activity" in html
    assert "Report Integrity Notes" in html
    assert len(reader.pages) >= 10
    assert "TraceHawk Incident Report" in text
    assert "Cross-source corroboration" in text


def test_asset_manifest_hashes_every_readme_artifact() -> None:
    manifest = json.loads((ROOT / "docs/assets/manifest.json").read_text(encoding="utf-8"))
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for relative_path, metadata in manifest["artifacts"].items():
        path = ROOT / relative_path
        assert path.is_file()
        assert metadata["bytes"] == path.stat().st_size
        assert metadata["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    for relative_path in (
        "docs/assets/demo/tracehawk-demo.gif",
        "docs/assets/demo/01-upload-analysis.png",
        "docs/assets/demo/02-incident-correlation.png",
        "docs/assets/demo/03-report-export.png",
        "docs/assets/reports/tracehawk-sample-incident.html",
        "docs/assets/reports/tracehawk-sample-incident.pdf",
    ):
        assert relative_path in readme


def test_distribution_manifests_exclude_source_only_output() -> None:
    overlay_root = ROOT / "public/github"
    manifest_root = overlay_root if overlay_root.is_dir() else ROOT
    manifest_paths = (
        manifest_root / "docs/assets/manifest.json",
        manifest_root / "docs/assets/reports/manifest.json",
    )

    for manifest_path in manifest_paths:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        artifacts = manifest["artifacts"]
        assert artifacts
        assert all(path.startswith("docs/assets/") for path in artifacts)
        assert not any(path.startswith("output/") for path in artifacts)
