# Changelog

## 0.0.1

Initial release.

- `list`, `table` and `table --live` generate process lists and `ps aux` style tables.
- `inject` starts a synthetic process tree in the real process table with bind, shadow and proc-self exe tiers, user switching, ptys, threads and VSZ/RSS padding.
- `stop` terminates a run from its pidfile; `--wait` stops it after a duration.
- `doctor` probes the environment; `log` and `load` generate activity and pressure.
- `corpus`, `check` and `unit` inspect the corpus and print a boot-time systemd unit.
- Static musl release binaries for seven targets, with `SHA256SUMS`.
