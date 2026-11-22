# Faultlab

Classify, isolate and exercise a degrading CPU core against a healthy control core.
Install: `sudo ./apply.sh --fault-cpu N [--control-cpu M]`, then reboot.
`--fault-cpu` is any logical CPU on the target physical core; siblings are auto-detected.
Control defaults to another core (same package/SMT width when possible).
QA Sentinels and `faultlab-crashes` follow `/etc/faultlab/config`; crash folders: `/var/log/faultlab/crashes`.
Lab: `sudo faultlab-mode lab` (session only; boot retires), then `sudo faultlab CMD`.
Verify: `sudo faultlab-verify`; crashes: `sudo faultlab-crashes list`; rollback: `sudo ./rollback.sh`.
Rescue USB: `examples/rescue-usb/`; docs: `docs/fault-core-plan.md`, `docs/crash-logging.md`; MIT.
