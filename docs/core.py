"""Offline spam signal and observable evidence; never authenticates a sender."""
from __future__ import annotations

import collections
import math
import re
import unicodedata
from urllib.parse import urlsplit

MAX_TEXT = 8192


def normalize(text):
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def features(text):
    words = re.findall(r"[a-z]+|<num>", re.sub(r"\d+", "<num>", normalize(text)))
    return words + [a + " " + b for a, b in zip(words, words[1:])]


class SpamModel:
    """Fixed alpha=1 multinomial NB; score is NOT a calibrated fraud probability."""

    def __init__(self, counts, docs):
        self.counts = counts
        self.docs = docs
        self.vocab = set(counts[0]) | set(counts[1])
        self.totals = [sum(c.values()) + len(self.vocab) for c in counts]

    @classmethod
    def train(cls, rows):
        counts = [collections.Counter(), collections.Counter()]
        docs = [0, 0]
        for label, text in rows:
            counts[label].update(features(text))
            docs[label] += 1
        if not all(docs):
            raise ValueError("Both classes required")
        return cls(counts, docs)

    def score(self, text):
        terms = collections.Counter(x for x in features(text) if x in self.vocab)
        values = [math.log(n / sum(self.docs)) for n in self.docs]
        for label in range(2):
            for token, count in terms.items():
                values[label] += count * math.log((self.counts[label].get(token, 0) + 1) / self.totals[label])
        delta = max(-700, min(700, values[0] - values[1]))
        return 1 / (1 + math.exp(delta)), len(terms)

    def export(self):
        return {"counts": [dict(c) for c in self.counts], "docs": self.docs,
                "algorithm": "multinomial-nb", "alpha": 1, "threshold": 0.9,
                "dataset": "UCI SMS Spam Collection, DOI 10.24432/C5CC84, CC BY 4.0"}

    @classmethod
    def load(cls, data):
        return cls([collections.Counter(c) for c in data["counts"]], data["docs"])


def expected_host(domain):
    if not isinstance(domain, str) or len(domain) > 253:
        raise ValueError("Expected domain must be a hostname")
    value = domain.strip().rstrip(".")
    if not value:
        return ""
    host = value.encode("idna").decode("ascii").lower()
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", host):
        raise ValueError("Use a domain obtained independently, without paths or credentials")
    return host


def analyze(text, model, domain=""):
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT:
        raise ValueError("Enter 1 to 8192 characters of message text")
    host_expected = expected_host(domain)
    score, known_terms = model.score(text)
    evidence = []
    links = []
    for match in re.finditer(r"(?:https?://|www\.)[^\s<>\"']+", text, re.I):
        raw = match.group().rstrip(".,);!]")
        try:
            url = urlsplit(raw if "://" in raw else "https://" + raw)
            host = (url.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
            if not host or len(host) > 253:
                raise ValueError("hostname")
            matching = bool(host_expected and (host == host_expected or host.endswith("." + host_expected)))
            warnings = []
            if url.username is not None:
                warnings.append("URL contains user information before the real host")
            if host_expected and not matching:
                warnings.append("Host differs from the independently supplied expected domain")
            if "xn--" in host:
                warnings.append("Internationalized domain: compare the exact spelling independently")
            if url.scheme.lower() != "https":
                warnings.append("Link does not use HTTPS")
            links.append({"host": host, "expected_domain_matches": matching,
                          "authenticity": "unverified", "warnings": warnings,
                          "start": match.start(), "end": match.start() + len(raw)})
        except (UnicodeError, ValueError):
            links.append({"host": None, "authenticity": "unverified",
                          "warnings": ["Malformed URL: do not open it"],
                          "start": match.start(), "end": match.end()})
    patterns = [
        ("Urgency or threatened consequence", r"\b(urgent|immediately|suspend(?:ed)?|last chance|within \d+ (?:hours?|minutes?))\b"),
        ("Request involving credentials", r"\b(password|otp|one[- ]time (?:code|password)|verification code|seed phrase)\b"),
        ("Payment or transfer request", r"\b(gift cards?|wire transfer|crypto(?:currency)?|send money|pay (?:now|a fee)|transfer (?:money|funds))\b"),
        ("Request for secrecy", r"\b(do not tell|don't tell|keep (?:this|it) secret|confidential payment)\b"),
    ]
    for label, pattern in patterns:
        for match in re.finditer(pattern, text, re.I):
            evidence.append({"label": label, "text": match.group(), "start": match.start(), "end": match.end(),
                             "meaning": "Observed language only; context and negation may change its meaning"})
    return {
        "sender_identity": "unverified",
        "spam_signal": "elevated" if score >= 0.9 and known_terms else "not elevated",
        "spam_model_score": round(score, 6),
        "score_meaning": "Uncalibrated model score for old English SMS spam; not a probability of fraud or identity verification",
        "known_model_terms": known_terms,
        "evidence": evidence, "links": links,
        "verification_steps": [
            "Pause any payment or disclosure of codes; these results cannot establish who sent the message.",
            "Use a contact or official app obtained independently, rather than a link or number in the message.",
            "Confirm the request through that independent channel before acting.",
        ],
        "limitations": [
            "A low spam score does not mean safe. New scams and unsupported languages can be missed.",
            "A matching domain or HTTPS does not authenticate the sender or prove the request is legitimate.",
            "This tool does not visit links, check reputation, inspect account state, or detect voice deepfakes.",
        ],
        "privacy": {"network_requests": 0, "message_stored": False},
    }
