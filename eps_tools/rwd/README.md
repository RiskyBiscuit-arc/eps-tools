# Local EPS firmware

This folder is intentionally retained. No `.rwd` firmware files are
distributed by eps-tools. Supply your own image for the exact EPS ECU,
retain a validated stock recovery image, and follow [the main README](../README.md).
Firmware files are ignored by Git. Do not commit them.

## Recommended flashing

From the parent `eps_tools/` folder on the comma, use the guided flasher:

```sh
PYTHONPATH=/data/openpilot python3 flash.py
```

It handles selection, validation, power prompts, bus detection, and a recommended
dry run before explicit flash confirmation. Its optional EPS communication check
is a sanity check, not an indication that the flash failed. `eps-diag.py --recovery`
adds troubleshooting guidance when investigating an unsuccessful flash.
`eps-update.py` remains the older manual alternative and the guided tool's backend.
