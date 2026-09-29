# Agent skills for FluxVM

Skills teach a coding agent (Claude Code, Codex, Cursor) to drive FluxVM without a source checkout. Each skill is a
folder with a `SKILL.md`. Copy a folder into your agent's skills directory (for Claude Code, `.claude/skills/`).

| Skill | Use it to |
|---|---|
| [`fluxvm-cli`](fluxvm-cli/SKILL.md) | Create, list, pause and delete VMs with `fluxctl` |
| [`fluxvm-egress-acl`](fluxvm-egress-acl/SKILL.md) | Write HTTP method/host/path rules for the egress proxy |
| [`fluxvm-sandbox`](fluxvm-sandbox/SKILL.md) | Use process sandboxes, file change-sets and dry-run |

The skills only restate what is in `docs/`. If a skill and the docs disagree, the docs win; fix the skill.
