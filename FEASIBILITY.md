# warpgate (+ the whole stack) on runloom — sync-port feasibility

warpgate is the top of a 4-repo stack: **warpgate → sidewire → namebump →
aionetiface**.  This is the stack-level result of porting all four to pure
synchronous code (no `async`/`await`, no asyncio bridge) running on runloom's
free-threaded 3.13t M:N scheduler via `runloom.run(8, main)`.  The aionetiface
port (its own `FEASIBILITY.md`) is the foundation; the three layers above reuse
its shims (`saio` asyncio-shim, `sock_transport`, `runloom_boot`).

## Headline

**The entire stack imports and runs as pure sync code.**  Every `async def` /
`await` is gone (AST-verified, 0 executable async nodes): aionetiface 54 files,
namebump 3, sidewire 12, warpgate 49.  `import warpgate` pulls the whole chain
in and exposes 471 public names with no event loop anywhere.

## What was validated on real M:N (`runloom.run(8/1, main)`)

| repo | checks | result |
| --- | --- | --- |
| aionetiface | TCP/UDP echo, 10 concurrent clients, real STUN WAN IP, real HTTP GET, full NIC discovery | **6/6** (run 1 & 8) |
| namebump | keypair gen, full ECDSA-signed packet wire roundtrip (sign/pack/unpack/verify + tamper) | **2/2** (run 8) |
| sidewire | MQTT wire codec, **real connect to test.mosquitto.org**, **real signed pub/sub** | **3/3** run(1); 2/3 run(8) (see below) |
| warpgate | full-stack sync import, core signal-proto registry, deterministic human nicknames, PNP ts-envelope + TLD codec | **4/4** (run 8) |

warpgate's *real P2P* (cross-NAT connect, hole punching) needs two peers behind
real NATs + MQTT/TURN infra and is out of scope on one Linux box — as are the
project's own connectivity tests, which need the same infra.  What runs here is
the import of the whole stack + warpgate's local protocol/naming logic.

## Findings the stack surfaced (beyond the aionetiface writeup)

1. **Deep pure-Python crypto needs a bigger goroutine stack.**  The `ecdsa`
   library's point math (`jacobi`, decompression) recurses deep.  On runloom's
   32 KB default goroutine stack that overflows the guard page → a hard
   **SIGSEGV** (sidewire's app-layer signing) or a `RecursionError` (namebump's
   verify).  Adaptive autosize can't save it — it grows toward an *observed*
   high-water mark over many completed goroutines, but a goroutine that recurses
   deep on its first run blows the page before autosize measures it.  Fix:
   `runloom_boot` pins a 1 MiB goroutine stack (virtual + pooled).  Separately,
   `saio.run_in_executor` now genuinely offloads to a worker thread (full stack)
   — which is exactly what aionetiface's `ecdsa_*_async` helpers intend.

2. **The one clean case of M:N parallelism breaking a single-threaded library.**
   sidewire's MQTT pub/sub delivers reliably under `run(1)` (cooperative, the
   asyncio-equivalent: 3/3) but **fails deterministically under `run(8)`** (3/3
   timeout — not broker flakiness).  sidewire's app-layer (shared `msg_queues`,
   ack futures, sequence state) was written for a single-threaded event loop;
   eight hubs executing its goroutines in parallel race that state.  This is the
   predicted axis made concrete: `run(1)` is the drop-in async-equivalent;
   `run(8)` additionally requires the library to be parallel-safe (locks around
   shared mutable state).  Everything else in the stack is fine under `run(8)`.

3. **Background tasks must become goroutines.**  sidewire's MQTT dispatcher was
   `asyncio.create_task(dispatcher(...))` — a forever republish loop.  After the
   strip that call runs eagerly and never returns; converted to a `runloom.go`
   goroutine whose teardown rides the existing `is_closed` flag.

## Verdict

The whole stack ports.  The networking foundation (aionetiface) and the
naming/crypto/signalling layers (namebump, sidewire) run as real blocking code
on the M:N scheduler against the live internet.  The remaining work to run the
*top* of the stack (warpgate P2P) for real is infra, not language-model: it
needs peers, NATs, MQTT and TURN — and, to use `run(8)` rather than `run(1)`,
the per-library shared state needs locking.  None of that is a runloom blocker;
it's the ordinary cost of taking a single-threaded async program genuinely
multi-core.
