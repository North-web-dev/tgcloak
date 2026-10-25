# Verification rig

Reproducible measurement of the FakeTLS ClientHello that a native Telegram
client (TDLib) emits, and its JA4 versus Chrome.

## Method
1. Build TDLib (`tdmtproto` static lib).
2. `tlsdump_harness.cpp` runs a `td::mtproto::TlsInit` actor against a local
   capture socket, so the exact FakeTLS ClientHello is captured on the wire.
3. Parse the ClientHello → JA3 / JA4.

## Result (captured, TDLib master, 2026-07)
```
TDLib native JA4:  t13d1516..._8daaf6152771_d8a2da3f94cd
Chrome:            t13d1516h2_8daaf6152771_b0da82dd1658
```
- ja4_a (version + cipher/ext counts): matches Chrome.
- ja4_b (cipher-suite hash): **identical to Chrome** — the cipher list is already
  Chrome's exact set and order.
- ja4_c (extension-set + sig-algs hash): **differs** — the sole residual tell.

## Conclusion
The native FakeTLS hello is already 2/3 identical to Chrome. The patch surface is
narrow: align the extension set (drop/adjust non-Chrome extensions such as the
`0x44cd` block) so ja4_c matches too. That single change ports across
tdesktop / DrKLO / TDLib (identical hello DSL).

`baseline_tdlib_hello.hex` — the captured 1724-byte ClientHello for reference.

## Reproduce the fingerprints

No TDLib needed to re-derive the JA3/JA4 from the committed capture:

```sh
python3 compute_ja4.py baseline_tdlib_hello.hex
# JA3:  ec05efb6022552676a685e4b52f36702
# JA4:  t13d1516h2_8daaf6152771_d8a2da3f94cd
```

`compute_ja4.py` is stdlib-only and ignores GREASE per the FoxIO JA4 spec
(sorted ciphers for `ja4_b`; sorted extensions minus SNI/ALPN, plus the
signature-algorithm list, for `ja4_c`).
