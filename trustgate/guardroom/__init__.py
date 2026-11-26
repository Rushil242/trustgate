"""The guard room: TrustGate as its own process, and in production its own OS user.

The hook the agent runs is a thin client. It holds no policy, no key and no
log; it passes the tool call to `trustgated` over a Unix socket and prints the
answer. Everything the gate depends on lives in the daemon's state folder,
which the agent's OS user cannot write once the daemon runs as `_trustgate`.

Two sockets, and the operating system enforces the difference:

* `agent.sock`, open to everyone: `decide`, `observe`, `status`. Nothing else.
* `admin.sock`, owner only (mode 0600): `resolve`, `policy-install`. A
  process that cannot open this file cannot approve anything.
"""
