"""Validates the 85%+ structural uniqueness claim for polymorphic morphing.

Generates N morphed variants of the same Python agent source, compares every
pair with difflib.SequenceMatcher, and asserts average uniqueness >= 0.85.
"""

import difflib
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from obfuscation.morphing import morph_python_source
from obfuscators.dynamic import obfuscate

SAMPLE_SOURCE = (Path(__file__).resolve().parent.parent /
                 "templates" / "agent_template.py").read_text()

NUM_VARIANTS = 10
THRESHOLD = 0.85


def _generate_variant(source):
    morphed = morph_python_source(source, intensity='high')
    morphed = obfuscate(morphed, 'python', {})
    return morphed


def _pairwise_uniqueness(variants):
    pairs = []
    for i in range(len(variants)):
        for j in range(i + 1, len(variants)):
            ratio = difflib.SequenceMatcher(None, variants[i], variants[j]).ratio()
            pairs.append(1.0 - ratio)
    return pairs


def test_structural_uniqueness():
    variants = [_generate_variant(SAMPLE_SOURCE) for _ in range(NUM_VARIANTS)]

    sizes = [len(v) for v in variants]
    uniqueness_scores = _pairwise_uniqueness(variants)
    avg = sum(uniqueness_scores) / len(uniqueness_scores)
    mn = min(uniqueness_scores)
    mx = max(uniqueness_scores)
    variance = sum((x - avg) ** 2 for x in uniqueness_scores) / len(uniqueness_scores)
    std = math.sqrt(variance)
    num_pairs = len(uniqueness_scores)

    print(f"\n{'=' * 60}")
    print(f"  Polymorphic Uniqueness Report")
    print(f"{'=' * 60}")
    print(f"  Variants generated : {NUM_VARIANTS}")
    print(f"  Pairwise comparisons : {num_pairs}")
    print(f"  Source size : {len(SAMPLE_SOURCE):,} bytes")
    print(f"  Variant sizes : {min(sizes):,} – {max(sizes):,} bytes")
    print(f"{'─' * 60}")
    print(f"  Average uniqueness : {avg:.1%}")
    print(f"  Min uniqueness : {mn:.1%}")
    print(f"  Max uniqueness : {mx:.1%}")
    print(f"  Std deviation : {std:.4f}")
    print(f"{'─' * 60}")
    print(f"  Threshold : {THRESHOLD:.0%}")
    print(f"  Result : {'PASS' if avg >= THRESHOLD else 'FAIL'}")
    print(f"{'=' * 60}\n")

    assert avg >= THRESHOLD, (
        f"Average uniqueness {avg:.1%} is below {THRESHOLD:.0%} threshold"
    )
    assert mn >= 0.50, (
        f"Minimum uniqueness {mn:.1%} is below 50% floor"
    )
