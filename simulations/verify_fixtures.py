"""
simulations/verify_fixtures.py

Runs every file in synthetic_data/ through the full Phase 4 + Phase 5
pipeline and prints what fired. This is what generated the table in
synthetic_data/README.md -- run it yourself any time you change a detector,
the policy YAML, or a fixture, to see exactly what changed.

Usage:
    python simulations/verify_fixtures.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detectors.engine import run_all, summarize  # noqa: E402
from normalization.normalizer import normalize_and_rescan  # noqa: E402

FIXTURE_DIR = Path(__file__).resolve().parent / "synthetic_data"


def main() -> None:
    fixtures = sorted(p for p in FIXTURE_DIR.glob("*.*") if p.suffix != ".md")
    if not fixtures:
        print(f"No fixtures found in {FIXTURE_DIR}")
        return

    for path in fixtures:
        text = path.read_text(encoding="utf-8")
        results = run_all(text, filename=str(path))
        summary = summarize(results)

        obf_results = normalize_and_rescan(text, run_all)
        obf_hits = [ob.technique for ob in obf_results if any(d.matched for d in ob.rescanned_detections)]

        print(f"\n{path.name}")
        print(f"  direct categories:      {summary['categories'] or '(none)'}")
        print(f"  matched detectors:      {summary['matched_detectors'] or '(none)'}")
        print(f"  needs_ai_review:        {summary['needs_ai_review']}")
        print(f"  obfuscation techniques: {obf_hits or '(none)'}")


if __name__ == "__main__":
    main()
