#!/usr/bin/env python3
"""Precision / recall measurement on a labelled set of .eml files.

Reads eval/labels.csv (filename,label) where label is phishing|suspicious|clean,
runs each email through the real analyzer, and reports:
  * a confusion matrix over the three verdicts
  * binary precision/recall/F1 treating {phishing, suspicious} as "flagged"

Usage:
    python eval/evaluate.py
    python eval/evaluate.py --samples tests/samples --labels eval/labels.csv

Note: with VirusTotal/Groq keys set, results reflect live services (and the VT
free-tier rate limit). Header, lookalike, deceptive-link and QR signals work
fully offline, so the evaluation still runs without any keys.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.core.analyzer import analyze  # noqa: E402

VERDICTS = ["phishing", "suspicious", "clean"]


def main() -> int:
    ap = argparse.ArgumentParser(description="PhishLens evaluation (precision/recall).")
    ap.add_argument("--samples", default=str(ROOT / "tests" / "samples"))
    ap.add_argument("--labels", default=str(ROOT / "eval" / "labels.csv"))
    args = ap.parse_args()

    labels_path = Path(args.labels)
    samples_dir = Path(args.samples)
    if not labels_path.exists():
        print(f"Labels file not found: {labels_path}")
        return 1

    rows = list(csv.DictReader(labels_path.open(encoding="utf-8")))
    if not rows:
        print("No rows in labels file.")
        return 1

    # confusion[true][pred]
    confusion = {t: {p: 0 for p in VERDICTS} for t in VERDICTS}
    results = []

    for row in rows:
        fname, true = row["filename"].strip(), row["label"].strip().lower()
        path = samples_dir / fname
        if not path.exists():
            print(f"  ! missing sample: {path}")
            continue
        report = analyze(path.read_bytes())
        pred = report["verdict"]
        confusion.setdefault(true, {p: 0 for p in VERDICTS})
        confusion[true][pred] = confusion[true].get(pred, 0) + 1
        results.append((fname, true, pred, report["score"]))

    # ---- per-email table ------------------------------------------------
    print("\n  Per-email results")
    print("  " + "-" * 60)
    print(f"  {'file':<30}{'true':<12}{'pred':<12}{'score'}")
    for fname, true, pred, score in results:
        flag = "" if true == pred else "   <-- mismatch"
        print(f"  {fname:<30}{true:<12}{pred:<12}{score}{flag}")

    # ---- confusion matrix ----------------------------------------------
    print("\n  Confusion matrix (rows = true, cols = predicted)")
    print("  " + "-" * 60)
    header = "  {:<12}".format("") + "".join(f"{p:<12}" for p in VERDICTS)
    print(header)
    for t in VERDICTS:
        print("  {:<12}".format(t) + "".join(f"{confusion[t][p]:<12}" for p in VERDICTS))

    # ---- binary metrics: flagged = phishing or suspicious --------------
    tp = fp = fn = tn = 0
    for fname, true, pred, _ in results:
        true_flag = true in ("phishing", "suspicious")
        pred_flag = pred in ("phishing", "suspicious")
        if true_flag and pred_flag:
            tp += 1
        elif not true_flag and pred_flag:
            fp += 1
        elif true_flag and not pred_flag:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(results) if results else 0.0

    print("\n  Binary metrics  (flagged = phishing OR suspicious)")
    print("  " + "-" * 60)
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  Precision: {precision:.2%}")
    print(f"  Recall:    {recall:.2%}")
    print(f"  F1:        {f1:.2%}")
    print(f"  Accuracy:  {accuracy:.2%}  ({len(results)} emails)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
