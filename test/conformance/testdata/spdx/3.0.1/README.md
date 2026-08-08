# SPDX 3.0.1 conformance documents

Documents written by other tools, kept here so the reader is checked against
SPDX 3 as it is written in the wild rather than only against what protobom
writes itself.

Source:  https://github.com/spdx/spdx-examples
Ref:     master
Commit:  2181917ef6ff74de89252ee785583c27a38d6199
License: CC0-1.0, per the source repository's README. Only the documents are
         vendored, not the repository's build scripts.

Six of the repository's twenty-six, chosen for what they exercise:

| Document | What it covers |
|---|---|
| `example1.spdx3.json` | the simple case: a package, its files, one root |
| `example6-lib.spdx3.json` | several packages, and a custom licence element |
| `example13.spdx3.json` | packages with no files, people and organizations |
| `examplemaven-0.0.1-enriched.spdx3.json` | packages enriched with identifiers and references |
| `appbomination.spdx3.json` | the largest of the software examples |
| `simplehtr-example.spdx3.json` | AI and dataset packages, which protobom drops, along with the relationships and roots that name them |

The whole set of twenty-six is read by the SPDX 3 library's own round-trip
tests, in the carabiner-dev/spdx3 repository.
