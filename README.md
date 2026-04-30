# depwatch

> Lightweight daemon that monitors Python project dependencies for outdated packages and CVEs, with configurable alerts.

---

## Installation

```bash
pip install depwatch
```

Or install from source:

```bash
git clone https://github.com/yourname/depwatch.git && cd depwatch && pip install .
```

---

## Usage

Point `depwatch` at your project directory and let it run in the background:

```bash
depwatch start --path /path/to/your/project --interval 24h
```

Check for issues immediately without starting the daemon:

```bash
depwatch scan --path /path/to/your/project
```

Configure alerts in `depwatch.yml`:

```yaml
alerts:
  email: you@example.com
  slack_webhook: https://hooks.slack.com/services/...
thresholds:
  cve_severity: high
  outdated_versions: 2
```

Run `depwatch --help` for a full list of options.

---

## Features

- 🔍 Detects outdated packages via PyPI
- 🛡️ CVE scanning powered by OSV.dev
- ⏱️ Configurable polling intervals
- 📣 Email and Slack alert integrations
- 🪶 Minimal footprint, no heavy dependencies

---

## License

MIT © 2024 Your Name