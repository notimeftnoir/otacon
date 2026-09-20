# CI/CD integration

_[← back to the README](../README.md)_ · [Usage](USAGE.md) · [Scoring](SCORING.md) · [Output](OUTPUT.md) · [CI/CD](CI.md) · [FAQ](FAQ.md) · [Design](DESIGN.md)

---

Add a brand-protection gate to your release pipeline. If a critical impersonation goes live, the pipeline fails.

### GitHub Actions

```yaml
name: brand-protection
on:
  schedule:
    - cron: "0 6 * * *"   # daily at 06:00 UTC
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: sudo apt-get install -y libc-ares-dev
      - run: pip install otacon
      - run: otacon scan example.com --json report.json --fail-on critical
      - if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: otacon-report
          path: report.json
```

### GitLab CI

```yaml
brand-protection:
  image: python:3.12
  before_script:
    - apt-get update && apt-get install -y libc-ares-dev
    - pip install otacon
  script:
    - otacon scan $CI_PROJECT_NAME.com --html report.html --fail-on high
  artifacts:
    when: always
    paths: [report.html]
  only: { refs: [schedules] }
```

---
