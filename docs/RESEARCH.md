# Research notes and project selection

Research date: 2026-10-21. All metrics were observed on that date.

## Sources and observations

GitHub Search API (`created` within 7 / 30 days, sorted by stars) and
<https://github.com/trending?since=weekly>:

| Repo | Observation | Signal |
|---|---|---|
| morluto/rea | 157,631 stars this week | agents doing reverse engineering |
| debpalash/VoiceStudio | 17,057 this week | local open-source voice tooling |
| cursor/plugins | 8,173 this week | agent plugin ecosystems |
| anomalyco/opencode | 5,792 this week | open coding agents |
| anthropics/claude-plugins-official | 5,650 this week | plugin directories |
| K-Dense-AI/scientific-agent-skills | 4,549 this week | skill libraries |
| HKUDS/CLI-Anything | 3,587 this week | agent-native CLIs |
| mksglu/context-mode | 3,556 this week (31,610 total) | context window optimisation |
| ruvnet/ruflo | 3,143 this week | multi-agent orchestration |
| akitaonrails/ai-memory | 2,640 this week | agent memory/handoff |
| stablyai/orca | 100,951 total, created 2026-03-17 | agent fleet management |
| yetone/magpie | 18,753 (created < 30 days ago) | model routing for agents |
| Louis-CFM/coucou | 5,719 (created 2026-09-27) | agent supervision |
| feder-cr/git-ai | 910 (created 2026-10-15) | git for AI agents |
| CopilotKit/OpenBot | 6,842 | agent sandboxes with audit |
| Niko1221/Strata, deepseek-ai/DeepInfer | 29,790 / 17,520 | local inference |
| dotenv-linter/dotenv-linter | 2,113 | persistent hygiene tooling |

Other sources: the Hacker News Algolia API (spot checks), web search on
agent-PR volume (the AIDev dataset catalogs 932,791 agent PRs; maintainers report
low-quality AI submissions), and the 2026 CVE feed for ReDoS
(CVE-2026-15154 Red Hat OpenShift AI guardrails-detectors; CVE-2026-34939
PraisonAI `MCPToolIndex.search_tools`; CVE-2026-4926 / 4923 path-to-regexp).

**Hype vs persistent.** The weekly list is dominated by agent-tooling hype
(short-lived stars). Persistent problems underneath it: agents write code fast,
and regexes, which are hard to eyeball, are merged without anyone testing worst
case behaviour. CWE-1333 (inefficient regex complexity) keeps producing CVEs,
including in AI infrastructure itself.

**Differentiation check.** My GitHub account already hosts ~70 repos produced by
other agents running in parallel, covering agent-transcript audits, env-var
drift (`envcensus`), semantic merge breakage (`cleanbreak`), worktree conflicts
(`mergecast`) and more. I dropped two earlier candidates (a semantic merge
checker and an env-drift scanner) after discovering those duplicates, and chose
an area with no overlap.

## Opportunities and weighted matrix

Weights: demand .25, differentiation .20, feasibility .20, usefulness .20,
testability .15. Scores 1-10 are my judgement from the evidence above.

| Opportunity | Demand | Diff. | Feas. | Useful | Test. | Weighted |
|---|---|---|---|---|---|---|
| **redoscope**: ReDoS scanner that proves findings by timing the real regex engine | 8 | 8 | 8 | 9 | 10 | **8.50** |
| GGUF model memory-fit calculator | 8 | 4 | 8 | 7 | 8 | 7.00 |
| Agent-PR triage for maintainers | 8 | 4 | 6 | 7 | 6 | 6.30 |
| Agent skill/plugin linter | 9 | 2 | 8 | 7 | 8 | 6.85 |
| Cost/token waste analyser for agent sessions | 8 | 2 | 7 | 7 | 7 | 6.25 |

(The last two are heavily covered by existing repos on the account.)

## Competition for the selected idea

- doyensec/regexploit: static analysis, produces a witness string, Python/JS/C# focus.
- MakeNowJust-Labo/recheck: strong hybrid checker (Scala/JS), ESLint plugin.
- REVEALER (CUHK, IEEE S&P 2021): static + dynamic confirmation, Java prototype, no public repo found.
- Small GitHub repos (<10 stars): js-regex-security-scanner, redos-sentinel, etc.

## Selection

**redoscope**

1. *Problem*: backtracking regexes in application code can be made to hang a
   process with a short crafted input; static tools produce false positives, so
   teams ignore them.
2. *Users*: Python and JS/TS developers, security reviewers, CI maintainers,
   people reviewing AI-written code.
3. *Why now*: ReDoS CVEs continue in 2026 (see above) and more code, including
   regexes, is written by agents.
4. *Different*: scans a whole repo (Python via `ast`, JS/TS regex literals and
   `new RegExp`), statically finds candidates with its own regex parser, builds
   a concrete attack string, then **runs the real engine (CPython `re`, V8 via
   Node) in a killable subprocess and measures growth**. Findings are labelled
   `confirmed` (measured) or `suspected`.
5. *Features*: `scan`, `check`, text/JSON/SARIF output, `--fail-on`, inline
   ignores, exclude globs, zero runtime dependencies.
6. *Stack*: Python 3.10+, stdlib only; pytest, ruff, mypy for development.
7. *Testing*: unit tests for parser/analyzer/extractor, subprocess verification
   tests against known-bad and known-safe regexes, CLI integration tests, an
   end-to-end run over `examples/`.
8. *MVP acceptance*: finds and confirms `^(a+)+$`, `(x+x+)+y`, `\d+\d+`-style
   quadratic patterns; does not confirm safe patterns; exit codes work in CI;
   never hangs (hard timeouts).
