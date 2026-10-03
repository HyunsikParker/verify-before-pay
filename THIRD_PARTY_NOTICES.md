# Third-party notices

The root MIT license covers original VerifyBeforePay application code, not the dataset-derived model or third-party runtime.

## SMS model

`model.json` and `docs/model.json` contain aggregate word and bigram counts trained from Almeida, T. & Hidalgo, J. (2011), *SMS Spam Collection*, UCI Machine Learning Repository, [DOI 10.24432/C5CC84](https://doi.org/10.24432/C5CC84), under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/). The training transformation and duplicate-group split are described in README.md. No raw SMS rows are included. This attribution does not imply endorsement by the dataset authors.

## Pyodide browser runtime

The files in `docs/vendor/pyodide/` are an unmodified subset of the official [Pyodide 314.0.7 core release](https://github.com/pyodide/pyodide/releases/tag/314.0.7). Pyodide is governed by MPL-2.0; its license is included as `docs/vendor/pyodide/LICENSE`. The corresponding source is available at [the pinned upstream tag](https://github.com/pyodide/pyodide/tree/314.0.7).

The runtime embeds CPython 3.14.2 and uses Emscripten 5.0.3. Their notices are included as `CPYTHON-LICENSE` and `EMSCRIPTEN-LICENSE` in the same directory. Source: [CPython v3.14.2](https://github.com/python/cpython/tree/v3.14.2) and [Emscripten 5.0.3](https://github.com/emscripten-core/emscripten/tree/5.0.3). Those files retain the upstream copyright and license text.

The runtime is self-hosted with the app. This project does not fetch optional Python packages or use Pyodide's package installer.
