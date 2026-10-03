"""One evaluation of a frozen split. Prints aggregate results, never corpus rows."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import time

from core import SpamModel, analyze, normalize


def metrics(labels, predictions):
    tp = sum(y == p == 1 for y, p in zip(labels, predictions))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, predictions))
    fn = sum(y == 1 and p == 0 for y, p in zip(labels, predictions))
    tn = sum(y == p == 0 for y, p in zip(labels, predictions))
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision,
            "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0}


def execute(root):
    started = time.monotonic()
    groups = {}
    conflicts = set()
    for line in (root / "SMSSpamCollection").read_text().splitlines():
        label, text = line.split("\t", 1)
        y = {"ham": 0, "spam": 1}[label]
        key = normalize(text)
        if key in groups and groups[key][0] != y:
            conflicts.add(key)
        groups[key] = (y, text)
    train, test = [], []
    for key, row in groups.items():
        if key in conflicts:
            continue
        (test if int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % 5 == 0 else train).append(row)
    model = SpamModel.train(train)
    labels = [y for y, _ in test]
    learned = metrics(labels, [int(model.score(text)[0] >= 0.9) for _, text in test])
    baseline = metrics(labels, [int(bool(re.search(r"\b(free|win|prize|urgent|cash|claim)\b", text, re.I))) for _, text in test])
    # Authored behavior checks; these are deliberately not called an independent holdout.
    messages = [
        "Please transfer funds now. Keep this secret.", "Do not give anybody your OTP.",
        "Your account is suspended. Enter your password.", "Hi, can we meet after class?",
        "I am your boss; buy gift cards immediately.", "This is your bank. Send money now.",
        "https://bank.example.attacker.example/login", "https://bank.example@attacker.example/",
        "https://bank.example/login", "http://bank.example/login", "https://support.bank.example/",
        "https://xn--pple-43d.example/", "https://[bad/", "www.attacker.example",
        "<img src=x onerror=alert(1)> https://attacker.example/", "hello\u202e.exe",
        "Hey mum, this is my new number, transfer money.", "Your parcel needs a fee; pay now.",
        "A recorded voice said to reveal my verification code.", "Prize winner! Send your seed phrase.",
        "This order was shipped; no action required.", "Korean text: 안녕하세요 회의 일정입니다",
        "Urgent meeting today. We will not ask for passwords.", "I need help with a school project.",
    ]
    passed = 0
    for text in messages:
        result = analyze(text, model, "bank.example")
        assert result["sender_identity"] == "unverified"
        assert result["privacy"] == {"network_requests": 0, "message_stored": False}
        assert all(link["authenticity"] == "unverified" for link in result["links"])
        assert "low spam score does not mean safe" in result["limitations"][0].lower()
        if "bank.example.attacker.example" in text or "bank.example@attacker.example" in text:
            assert result["links"][0]["expected_domain_matches"] is False
        passed += 1
    seconds = time.monotonic() - started
    model_data = json.dumps(model.export(), separators=(",", ":"))
    footprint = sum(p.stat().st_size for p in root.iterdir() if p.is_file()) + len(model_data.encode())
    gate = learned["precision"] >= .94 and learned["recall"] >= .82 and learned["f1"] >= .88 and passed >= 24 and seconds <= 120 and footprint <= 256 * 1024 * 1024
    # Model weights remain private development artifacts until their release checks.
    (root / "model.json").write_text(model_data)
    (root / "model.json").chmod(0o600)
    result = {"experiment_id": "forgehacks-local-scam-evidence-v1-20261003", "gate_passed": gate,
              "train_groups": len(train), "test_groups": len(test), "conflicting_groups_removed": len(conflicts),
              "model": learned, "fixed_keyword_baseline": baseline, "model_f1_delta": learned["f1"] - baseline["f1"],
              "authored_functional_cases_passed": passed, "authored_functional_cases_total": len(messages),
              "runtime_seconds": seconds, "artifact_bytes": footprint,
              "model_sha256": hashlib.sha256(model_data.encode()).hexdigest(),
              "evaluation_count": 1, "holdout_rows_printed": False,
              "scope": "Old English SMS spam aggregate holdout; authored behavior invariants. No modern fraud generalization, user benefit, official judging score or award established."}
    (root / "falsifier-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 0 if gate else 2


if __name__ == "__main__":
    import sys
    raise SystemExit(execute(Path(sys.argv[1]).resolve()))
