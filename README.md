# VerifyBeforePay

VerifyBeforePay helps someone pause and inspect a suspicious request before sending money or revealing a code. It runs a small spam model locally, shows observable request wording and the real host in a pasted link, and explains how to check the request through an independent channel.

The sender always remains **unverified**. A low spam score, HTTPS, or a matching domain does not mean that a message is safe. The app never visits pasted links.

[Watch the public functional walkthrough (3:19)](https://hyunsikparker.github.io/verify-before-pay/walkthrough.html). It shows the working browser app with fictional messages and synthetic narration. The edited walkthrough is not a continuous recording; its transcript and captions are provided with the video.

## Browser demo

[Open VerifyBeforePay](https://hyunsikparker.github.io/verify-before-pay/). The page downloads its Python runtime, fixed model, and app files from the same static site. After loading, the unchanged Python analysis code runs in the browser through Pyodide. Message text is not uploaded, pasted links are not visited, and no external inference service is used.

The interface does not save messages or use analytics. Clear removes the input and displayed results; it is not a secure memory wipe. Browser extensions, browser history, and the hosting service are outside the app's control. Hosting logs may record ordinary requests for app files, not the message text.

To serve the same browser version locally:

```sh
python3 -m http.server 8764 --bind 127.0.0.1 --directory docs
```

Open `http://127.0.0.1:8764`. First load downloads about 14 MB of local runtime and app files. No installation, API key, account, or paid service is needed to examine a message.

## Python-only local version

Python 3.10 or later is sufficient. No packages, accounts, or paid services are required.

```sh
python3 server.py --model model.json --port 8763
```

Open `http://127.0.0.1:8763`. Use the explicitly fictional example, or enter a message and an optional organization domain obtained independently. Clear removes the input and the displayed results.

The server binds to loopback, keeps no request logs, and does not save message text. The interface loads local files and calls the local analysis endpoint. It uses no analytics or external inference service. Do not expose this development server publicly.

## How it works

The model is multinomial Naive Bayes with word and bigram features and fixed Laplace smoothing of 1. A score of at least 0.9 produces an elevated spam signal. This score is uncalibrated and concerns an older English SMS spam corpus, not the probability that a request is fraudulent.

Separate checks extract the actual URL host, identify user information before a host, compare it with an independently supplied expected domain, and show observed urgency, credential, payment, or secrecy wording. Context and negation can change the meaning of those cues. The verification steps direct the user to a separately obtained contact or official app.

Before displaying a link host, both interfaces also parse the extracted link with the browser's URL parser without visiting it. If it is malformed, or its host differs from the frozen Python parser's interpretation, the interface shows a warning instead of either host. Backslashes, some internationalized domains, and invalid ports can trigger this check. This display check does not change the frozen Python analysis or model scores; the Python endpoint still returns the original analysis output.

## Opening evaluation

Before model computation, the mechanism, split, thresholds, runtime cap, and stop conditions were registered. Normalized duplicate messages were grouped. Groups whose normalized-text SHA-256 prefix modulo 5 equals 0 formed the untouched test partition; the remaining groups trained the model. Test content did not contribute to the vocabulary or threshold choice.

One evaluation used 4,136 training groups and 1,023 test groups:

| Measure | Learned model | Fixed keyword baseline |
| --- | ---: | ---: |
| Spam precision | 0.992 | 0.784 |
| Spam recall | 0.908 | 0.443 |
| Spam F1 | 0.948 | 0.566 |

The model had 119 true positives, 1 false positive, 12 false negatives, and 891 true negatives. A separate set of 24 authored functional cases passed the identity, link-host, and output behavior checks. Those authored cases are not independent evidence of generalization. Software checks of the Python-only server cover malformed input, size limits, origin rejection, path traversal, and JSON-only requests. Its Chrome interface was inspected at normal width and a narrow 320px viewport.

The browser package preserves the evaluated model and analysis-code hashes. A separate software check compares complete outputs, including validation errors, for 34 synthetic cases between native Python and browser-runtime Python. Cases cover URL user information, subdomains, Unicode normalization, IDNA, malformed links, unsupported-language text, and input limits. This is runtime-equivalence testing, not another model evaluation:

```sh
node tests/runtime-parity.mjs
```

Browser regression checks exercise the static demo and Python-server interface with synthetic links, including ambiguous hosts, invalid ports, and Unicode offsets. With Playwright for Python and Chromium already installed, run:

```sh
python3 tests/browser-links.py --chromium /usr/bin/chromium
```

This checks software behavior and preserves the opening evaluation's model and code hashes. It does not train the model, reopen the SMS holdout, or establish improved fraud detection.

The holdout was evaluated once and was not used for tuning. Do not rerun `falsifier.py` against that exposed partition to justify a revised model. A new mechanism needs a separately registered evaluation.

## Limits

The data predates current AI-enabled fraud. These results do not establish modern scam detection, user outcomes, sender authenticity, voice-deepfake detection, official judging points, or an award. Unsupported languages and new wording may be missed. URL checks do not inspect reputation, DNS, certificates, or account state.

## Sources and event work

Dataset: Almeida, T. & Hidalgo, J. (2011), *SMS Spam Collection*, UCI Machine Learning Repository, [DOI 10.24432/C5CC84](https://doi.org/10.24432/C5CC84). The dataset is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The included model was trained from that dataset; no raw SMS rows are bundled.

This project targets ForgeHacks' **AI + Cybersecurity** prompt about recognizing, preventing, verifying, or responding to scams, impersonation, and fraud. The application code and model were created after the public kickoff on October 3, 2026. Python's standard library, Pyodide, and the pre-existing UCI dataset are reused components. Coding assistants were used to implement and check the project. No sponsor credits were activated.

Original application code is MIT-licensed. The UCI-derived model attribution and bundled runtime licenses are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). No raw SMS rows are bundled. The runtime and model are fixed; the app does not learn from pasted messages.
