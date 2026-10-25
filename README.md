# tgcloak

**A TLS-fingerprint cloaking protocol for Telegram — make an MTProto proxy
connection indistinguishable from an ordinary browser, so it survives
ClientHello fingerprinting (JA3/JA4) without a VPN.**

> Contact / discussion: Telegram **[@North_web](https://t.me/North_web)**

---

## Why this exists

Telegram ships an MTProxy mode called **FakeTLS** (the `ee` secret): the client
wraps its MTProto stream in something that *looks* like a TLS 1.3 session to a
cover domain, so a censor doing SNI/plaintext inspection sees "HTTPS to
`www.google.com`" instead of an obvious proxy.

That trick is no longer enough. Modern censorship stacks — notably Russia's
**TSPU** — fingerprint the **ClientHello itself** with **JA3/JA4**. Telegram's
FakeTLS ClientHello is a hand-crafted, *fixed* byte sequence. It approximates a
browser but is not byte-identical to one, so it produces a **stable, catalogued
fingerprint**. In April–May 2026 TSPU used exactly this to run a wave of
FakeTLS blocks; Telegram could only respond by *patching the client's
ClientHello* (tdesktop #30513, DrKLO #1949 — e.g. extension `0xfe02` → `0xfe0d`,
random field 20 → 32 bytes).

**The fingerprint is decided client-side, on the wire the app puts out.** No
server-side proxy change can fix it. The durable fix is to make the client emit
a *byte-accurate, current* browser ClientHello. That is what tgcloak specifies.

---

## The core principle

> **Coherence beats camouflage.** A hand-rolled "browser-like" hello is a
> fingerprint. A *real* browser hello — reproduced byte-for-byte, GREASE and
> extension order included — is indistinguishable from the millions of Chrome
> handshakes a censor cannot afford to block.

tgcloak replaces the FakeTLS ClientHello with the exact ClientHello a current
Chrome build sends, sourced from a maintained fingerprint template
([uTLS](https://github.com/refraction-networking/utls)). The MTProto payload
still rides inside the TLS records exactly as FakeTLS defines; only the visible
handshake fingerprint changes — from "Telegram" to "Chrome".

---

## How it works

```
Telegram MTProto stream
        │  (obfuscated2, unchanged)
        ▼
FakeTLS framing (ee-secret, unchanged)  ──►  records: \x16\x03\x01 … \x17\x03\x03 …
        │
        ▼
ClientHello  ◄── REPLACED: byte-exact current-Chrome hello (uTLS template)
        │        • real cipher list, GREASE, extension order
        │        • ALPN h2, key_share, supported_versions, sig-algs — Chrome's
        │        • 32-byte random slot carries the FakeTLS HMAC digest
        ▼
On the wire: JA3/JA4 == Chrome. TSPU sees ordinary HTTPS.
```

The FakeTLS authentication is untouched: the ClientHello's 32-byte `random`
field still carries `HMAC-SHA256(secret, hello)` with a little-endian timestamp,
and the proxy still answers with a matching ServerHello. tgcloak only changes
which *shape* of ClientHello those bytes live in.

### Two deployment modes

**1. Local relay (no app change) — `tgrelay`.**
A small binary on the user's device presents a normal MTProxy on
`127.0.0.1`. Telegram connects to it natively (one tap, `tg://proxy`); the relay
re-dials the upstream MTProxy while emitting the Chrome ClientHello via uTLS. The
app's own (flagged) fingerprint never reaches the censor — only the relay's
Chrome one does. No rebuild of the app, and no change to the upstream proxy.
(Design; the relay binary is not yet published in this repo — see Status.)

**2. Native client patch (durable) — a Telegram fork.**
Patch the FakeTLS ClientHello generator directly in the client so the app itself
emits the Chrome hello. Same effect, zero extra software: install the fork, plug
in any MTProxy, done. The patch point is the *same hand-written ClientHello DSL*
in every official client:

| Client | File | Function |
| --- | --- | --- |
| Desktop (tdesktop) | `mtproto/details/mtproto_tls_socket.cpp` | `PrepareClientHelloRules()` |
| Android (DrKLO) | `TMessagesProj/jni/tgnet/ConnectionSocket.cpp` | `TlsHello::getDefault()` |
| TDLib | `td/mtproto/TlsInit.cpp` | `TlsHello::get_default()` |

All three build the hello from the identical `Op::string / Op::grease /
Op::domain / Op::key` mini-DSL, so a single Chrome-exact hello ports across them
verbatim.

---

## Threat model — honest scope

**What tgcloak defeats:**
- **JA3 / JA4 ClientHello fingerprinting** — the mechanism behind the 2026
  FakeTLS blocking waves. With a byte-exact Chrome hello there is no
  Telegram-specific tell to catalogue.
- **Passive TLS classification** of the handshake shape.

**What it does NOT fix (be clear-eyed):**
- **Server-side / JARM detection** of the proxy — the cover domain's TLS stack
  must actually match the domain it imitates (Reality-style real-backend
  fallback). Audit this with `mtaudit`.
- **Metadata heuristics** — connection volume, duration, and **datacenter-ASN**
  targeting (TSPU freezes long TLS flows to foreign DC ASNs). Use residential /
  in-country egress and reasonable pacing.
- **SNI↔IP mismatch** — the cover domain should plausibly resolve to the proxy
  IP.

tgcloak closes the *client fingerprint* hole specifically. It is one layer, not
a silver bullet.

---

## Verification

Fingerprint claims must be measured, not asserted. What is in **this** repo is a
reproducible measurement of the *problem*: the ClientHello a current native
Telegram client actually emits, and how far it already is from Chrome.

`verification/` contains:

- **`baseline_tdlib_hello.hex`** — the real 1724-byte FakeTLS ClientHello a
  native TDLib build (master, 2026-07) puts on the wire, captured off a local
  socket.
- **`tlsdump_harness.cpp`** — the capture harness that produced it (drives
  `td::mtproto::TlsInit` against a loopback socket; requires a TDLib checkout —
  see Build & reproduce).
- **`compute_ja4.py`** — a dependency-free JA3/JA4 calculator so anyone can
  re-derive the fingerprints below straight from the committed capture.

**Measured result** (reproducible: `python3 verification/compute_ja4.py
verification/baseline_tdlib_hello.hex`):

```
Native TDLib FakeTLS   t13d1516h2_8daaf6152771_d8a2da3f94cd   (captured, this repo)
Chrome (target)        t13d1516h2_8daaf6152771_b0da82dd1658   (reference profile)
```

| JA4 segment | Native FakeTLS | vs Chrome |
| --- | --- | --- |
| `ja4_a` — version / counts / ALPN | `t13d1516h2` | **matches** |
| `ja4_b` — cipher-suite hash | `8daaf6152771` | **matches** (identical cipher list + order) |
| `ja4_c` — extension + sig-alg hash | `d8a2da3f94cd` | **differs** |

So the native hello is **already 2/3 identical to Chrome**. The residual tell is
`ja4_c`: the extension set still carries a non-Chrome marker (the `0x44cd`
block). That is the narrow surface the cloak has to align, and it is the same
hello DSL across all three clients.

> The Chrome JA4 above is a published reference profile used as the target, not a
> value measured in this repo. Measuring an *outgoing cloaked* handshake end to
> end needs a live reflector (see `fpcheck`); this repo does not ship a captured
> cloaked hello, so no such hash is claimed here.

Companion tooling (separate repos):

- **[fpcheck](https://github.com/North-web-dev/fpcheck)** — self-hosted
  JA3/JA4/JA4H + HTTP/2 fingerprint reflector. Point a client at it, read its
  exact JA4.
- **[mtaudit](https://github.com/North-web-dev/mtaudit)** — client-side
  detectability auditor (JARM, active-probe, ASN) for the proxy leg.

---

## Build & reproduce

**Re-derive the fingerprints (no toolchain):**

```sh
python3 verification/compute_ja4.py verification/baseline_tdlib_hello.hex
# -> t13d1516h2_8daaf6152771_d8a2da3f94cd
```

**Re-capture the native hello (needs TDLib):** `tlsdump_harness.cpp` links
against TDLib's `tdmtproto` and uses its private `td/mtproto/TlsInit.h`, so it
builds inside a TDLib checkout, not standalone. Point a listener at
`127.0.0.1:7000`, run the harness, and dump the bytes it writes. See
`verification/README.md`.

---

## Status — what is in this repo

- **Protocol / principle** — specified here.
- **Verification rig** — present and reproducible: captured native FakeTLS
  hello + JA4 calculator; confirms the 2/3 match and isolates the `ja4_c` tell.
- **Reference relay (`tgrelay`)** — *design, not yet published here.* The intended
  shape (obfuscated2 codec + uTLS browser-hello dial + bidirectional bridge) is
  described above under "Two deployment modes"; the implementation is not part of
  this repository yet.
- **Native client patches** — patch points located in all three clients (table
  above); the Chrome-exact hello is not yet committed here.
- **Auditing** — `fpcheck` and `mtaudit` live in their own repos.

---

## Disclaimer

For **educational and anti-censorship research**. Provided **as is, without
warranty of any kind**. Automating or modifying a third-party client may violate
that service's Terms of Service; you are solely responsible for lawful use in
your jurisdiction. The authors accept no liability.

## Support

If this work is useful to you, a ⭐ on the repo helps. Donations keep the research
and tooling maintained:

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |

## License

MIT — see [LICENSE](LICENSE).
