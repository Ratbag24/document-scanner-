# YARA rules

Drop `.yar` / `.yara` files in this directory and point `[yara].rules_dir` at it.
Every file is compiled into one ruleset at startup; a rule that fails to compile
disables the whole YARA detector, so validate new rules with
`yara -w yourrule.yar /bin/ls` before deploying them.

## Metadata this scanner reads

- `severity = "malicious" | "suspicious" | "info"` — controls the verdict a match
  produces. **Defaults to `malicious` when absent**, so set `suspicious` on any
  rule that has false positives you are willing to live with.
- `description` — shown in alerts. Write it for whoever reads the alert at 2am.

## Getting a real ruleset

The bundled rules are a starting point, not coverage. Established free sets:

- **YARA Forge** (<https://yarahq.github.io/>) — curated, deduplicated, weekly
  releases; the easiest way to get broad coverage in one file.
- **Neo23x0/signature-base** — the rules behind Loki/Thor, high signal.
- **Elastic protections-artifacts** — strong on Linux and macOS.
- **Awesome-YARA** — an index of the rest.

Check licences before redistributing; most are permissive but not all.
