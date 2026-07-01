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
Chrome one does. Works today, no rebuild.

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

Fingerprint claims must be measured, not asserted. This project ships its own
test rig:

- **[fpcheck](https://github.com/North-web-dev/fpcheck)** — self-hosted
  JA3/JA4/JA4H + HTTP/2 fingerprint tester. Point a client at it, read its exact
  JA4.
- **[mtaudit](https://github.com/North-web-dev/mtaudit)** — server-side
  detectability auditor (JARM, active-probe, ASN) for the proxy leg.

**Measured result.** A uTLS `HelloChrome` ClientHello, captured by fpcheck:

```
Real Chrome        t13d1516h2_8daaf6152771_b0da82dd1658
tgcloak (uTLS)     t13d1516h2_8daaf6152771_………………………   ← JA4 a + b identical
curl (baseline)    t13i3112h2_e8f1e7e78f70_………………………   ← unrelated fingerprint
```

The version + cipher-suite + ALPN core (`t13d1516h2`) and the cipher hash
(`8daaf6152771`) match Chrome byte-for-byte. Pinning the exact current Chrome
template closes the remaining extension-hash segment.

---

## Status

- **Protocol / principle** — specified here.
- **Reference relay (`tgrelay`)** — implemented: obfuscated2 codec, uTLS
  browser-hello dial, bidirectional bridge. Chrome handshake verified live.
- **Native client patches** — patch points located in all three clients; the
  Chrome-exact hello is finalized on the TDLib testbed (buildable + fpcheck-
  verifiable) before porting to the desktop/Android forks.
- **Auditing** — `fpcheck` + `mtaudit` operational.

---

## Disclaimer

For **educational and anti-censorship research**. Provided **as is, without
warranty of any kind**. Automating or modifying a third-party client may violate
that service's Terms of Service; you are solely responsible for lawful use in
your jurisdiction. The authors accept no liability.

## License

MIT — see [LICENSE](LICENSE).
