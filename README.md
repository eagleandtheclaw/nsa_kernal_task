# nsa_kernal_task

Public, sanitized `kernel_task` (PID 0) stack samples from a macOS collector.
The repository name retains the requested spelling `kernal`; the process name
is `kernel_task`.

Each `samples/YYYY-MM-DD/*.json.xz` file contains one one-second stack report,
sample count, UTC capture time, SHA-256 of the sanitized report, SHA-256 of
the private signed source record, and a link to the prior public sample. The
reports omit host metadata, thread addresses, thread names, binary UUIDs,
binary inventory, home paths, email addresses, network addresses, and
credential-looking strings. Public files are typically a few kilobytes each.

The original, full reports remain in a separate private repository and in a
root-owned local archive. Public derivatives are SHA-256 linked and can be
checked with `python3 verify_public.py`. They do not carry the root signing
key's signature. Independent confirmation that a derivative came from its
stated signed original requires access to that private original.

`src/capture.py` is the exact installed collector source, copied only after
its hash and identifier scan pass. `SOURCE_HASHES.json` records its SHA-256.
The login publisher and deployment settings stay private because they contain
machine-specific account paths. `verify_public.py` checks the public source
hash as well as the sample chain.

The collector targets starts 25 to 50 seconds apart using the operating
system's cryptographic random source. A login-session publisher attempts a
new public commit at a random 3 to 6 minute interval, including heartbeat
commits when no sample is pending. Sleep, network loss, login state, or system
faults can create gaps; timestamps and heartbeat history show the observed
record rather than guaranteeing continuous coverage.

Stack samples show kernel activity during each sampling window. They do not
by themselves identify an actor or capture every action on the machine.
