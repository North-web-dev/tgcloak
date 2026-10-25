#!/usr/bin/env python3
"""Compute JA3 / JA4 from a captured TLS ClientHello.

Dependency-free (stdlib only). Reproduces the fingerprints quoted in
verification/README.md directly from the committed capture, so the claim is
checkable by anyone:

    python3 compute_ja4.py baseline_tdlib_hello.hex

Input is a hex dump of the full TLS record (starting 0x16 0x03 0x01 ...),
as produced by the capture harness. JA4 follows the FoxIO specification
(https://github.com/FoxIO-LLC/ja4): GREASE values are ignored; for JA4_b the
cipher list is sorted; for JA4_c the extension list is sorted with SNI (0x0000)
and ALPN (0x0010) removed, then the signature-algorithm list is appended in
order.
"""
import sys
import hashlib

GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
          0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


def is_grease(v):
    return v in GREASE


def parse(data):
    if data[0] != 0x16:
        raise ValueError("not a TLS handshake record")
    p = 5
    if data[p] != 0x01:
        raise ValueError("not a ClientHello")
    p += 4
    client_version = data[p:p + 2]; p += 2
    p += 32                                   # random
    sid_len = data[p]; p += 1 + sid_len       # session id
    cs_len = int.from_bytes(data[p:p + 2], 'big'); p += 2
    ciphers = [int.from_bytes(data[p + i:p + i + 2], 'big')
               for i in range(0, cs_len, 2)]
    p += cs_len
    comp_len = data[p]; p += 1 + comp_len
    ext_total = int.from_bytes(data[p:p + 2], 'big'); p += 2
    ext_end = p + ext_total

    extensions = []
    sni_present = False
    alpn_vals, supported_versions, sig_algs = [], [], []
    ecurves, ecpf = [], []
    while p < ext_end:
        et = int.from_bytes(data[p:p + 2], 'big'); p += 2
        el = int.from_bytes(data[p:p + 2], 'big'); p += 2
        body = data[p:p + el]; p += el
        extensions.append(et)
        if et == 0x0000:
            sni_present = True
        elif et == 0x0010:                     # ALPN
            lp = 2
            while lp < len(body):
                l = body[lp]; lp += 1
                alpn_vals.append(body[lp:lp + l].decode('latin1')); lp += l
        elif et == 0x002b:                     # supported_versions
            lp = 1
            while lp < len(body):
                supported_versions.append(int.from_bytes(body[lp:lp + 2], 'big')); lp += 2
        elif et == 0x000d:                     # signature_algorithms
            l = int.from_bytes(body[0:2], 'big'); lp = 2
            while lp < 2 + l:
                sig_algs.append(int.from_bytes(body[lp:lp + 2], 'big')); lp += 2
        elif et == 0x000a:                     # supported_groups
            l = int.from_bytes(body[0:2], 'big'); lp = 2
            while lp < 2 + l:
                v = int.from_bytes(body[lp:lp + 2], 'big')
                if not is_grease(v):
                    ecurves.append(v)
                lp += 2
        elif et == 0x000b:                     # ec_point_formats
            l = body[0]; lp = 1
            while lp < 1 + l:
                ecpf.append(body[lp]); lp += 1
    return dict(client_version=client_version, ciphers=ciphers,
                extensions=extensions, sni=sni_present, alpn=alpn_vals,
                supported_versions=supported_versions, sig_algs=sig_algs,
                ecurves=ecurves, ecpf=ecpf)


def ja3(f):
    ciph = [c for c in f['ciphers'] if not is_grease(c)]
    exts = [e for e in f['extensions'] if not is_grease(e)]
    s = "%d,%s,%s,%s,%s" % (
        int.from_bytes(f['client_version'], 'big'),
        "-".join(map(str, ciph)),
        "-".join(map(str, exts)),
        "-".join(map(str, f['ecurves'])),
        "-".join(map(str, f['ecpf'])))
    return s, hashlib.md5(s.encode()).hexdigest()


def ja4(f):
    ciph = [c for c in f['ciphers'] if not is_grease(c)]
    exts_all = [e for e in f['extensions'] if not is_grease(e)]
    vers = {0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10'}
    sv = [v for v in f['supported_versions'] if not is_grease(v)]
    hi = max(sv) if sv else int.from_bytes(f['client_version'], 'big')
    a_ver = vers.get(hi, '00')
    sni = 'd' if f['sni'] else 'i'
    alpn = (f['alpn'][0][0] + f['alpn'][0][-1]) if f['alpn'] else '00'
    a = "t%s%s%02d%02d%s" % (a_ver, sni, min(len(ciph), 99),
                             min(len(exts_all), 99), alpn)
    b_in = ",".join("%04x" % c for c in sorted(ciph))
    b = hashlib.sha256(b_in.encode()).hexdigest()[:12]
    ext_c = sorted(e for e in exts_all if e not in (0x0000, 0x0010))
    c_in = ",".join("%04x" % e for e in ext_c) + "_" + \
           ",".join("%04x" % s for s in f['sig_algs'])
    c = hashlib.sha256(c_in.encode()).hexdigest()[:12]
    return a, b, c, b_in, c_in


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "baseline_tdlib_hello.hex"
    data = bytes.fromhex(open(path).read().strip().replace('\n', ''))
    f = parse(data)
    print("bytes:               %d" % len(data))
    print("cipher suites:       %d (incl. GREASE)" % len(f['ciphers']))
    print("extensions:          %d (incl. GREASE)" % len(f['extensions']))
    print("ALPN:                %s" % ", ".join(f['alpn']))
    j3s, j3 = ja3(f)
    a, b, c, b_in, c_in = ja4(f)
    print()
    print("JA3:                 %s" % j3)
    print("JA4:                 %s_%s_%s" % (a, b, c))
    print("  JA4_a:             %s" % a)
    print("  JA4_b (ciphers):   %s" % b)
    print("  JA4_c (ext+sig):   %s" % c)
    print()
    print("JA4_b raw:           %s" % b_in)
    print("JA4_c raw:           %s" % c_in)


if __name__ == "__main__":
    main()
