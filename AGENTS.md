# Agent execution policy — usayd-web

Read `gemini/GEMINI_MASTER_AUTONOMOUS_OPERATOR_PROMPT.md` from the handoff package, the ORIGINAL source specs and the exact `planning/tasks/<ID>.md` before each change.
This is one of THREE independent repositories; keep contracts versioned, do not move to monorepo.
Target component: `web`. Changes may reference shared contracts but never silently modify a different repository.
Scope one Jira ticket per branch/PR, verified tests, safety review, branch protection, no fabricated API, no unapproved product/legal/academic decisions, no bypass of CI.
For approved design implement original styles and accessibility; for API use MySQL 8.4 transactions and negative policy tests; for mobile distinguish fixtures from real integration.
