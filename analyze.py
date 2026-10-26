#!/usr/bin/env python3
"""
Reassemble the Fitbit Air's IP-over-BLE traffic from an iOS Bluetooth capture
and parse the DTLS 1.2 handshake.

Usage:
    # 1. Export the band's ATT writes/notifications to a TSV first:
    #    tshark -r bt.pklg -Y "bthci_acl.chandle == 0x0040 && btatt.value" \
    #      -T fields -e frame.number -e btatt.opcode -e btatt.value > att.tsv
    # 2. python3 analyze.py

Replace the connection handle (0x0040) with your band's handle if different.
"""
import collections

ATT_WRITE = {"0x12", "0x52"}       # Write Request / Write Command
ATT_NOTIFY = {"0x1b", "0x1d"}      # Handle Value Notification / Indication

streams = collections.defaultdict(bytearray)
for line in open("att.tsv"):
    parts = line.strip().split("\t")
    if len(parts) < 3 or not parts[2]:
        continue
    op, val = parts[1], bytes.fromhex(parts[2].replace(":", ""))
    if len(val) <= 1:
        continue
    direction = ("phone->band" if op in ATT_WRITE
                 else "band->phone" if op in ATT_NOTIFY else None)
    if direction:
        streams[direction] += val[1:]  # drop the 1-byte L2CAP/stream counter


def ip_packets(data):
    """Extract UDP payloads from a byte stream of IPv4/UDP packets."""
    i, out = 0, []
    while i + 28 <= len(data):
        # IPv4 (0x45), proto UDP (0x11), link-local src (169.254.x.x)
        if data[i] == 0x45 and data[i + 9] == 0x11 and data[i + 12:i + 14] == b"\xa9\xfe":
            total = int.from_bytes(data[i + 2:i + 4], "big")
            if total < 28 or i + total > len(data):
                break
            out.append(data[i + 28:i + total])  # 20B IP + 8B UDP header
            i += total
        else:
            i += 1
    return out


HS_TYPES = {1: "ClientHello", 2: "ServerHello", 3: "HelloVerifyRequest",
            11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest",
            14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange",
            20: "Finished"}

CIPHERS = {0xC0A8: "PSK_AES_128_CCM_8", 0xC0A4: "PSK_AES_128_CCM",
           0x00A8: "PSK_AES_128_GCM_SHA256", 0xC0AE: "ECDHE_ECDSA_AES_128_CCM_8",
           0xC02B: "ECDHE_ECDSA_AES_128_GCM_SHA256",
           0xD001: "ECDHE_PSK_AES_128_GCM_SHA256", 0xD003: "ECDHE_PSK_AES_128_CCM_8_SHA256",
           0xD005: "ECDHE_PSK_AES_128_CCM_SHA256", 0xC037: "ECDHE_PSK_AES_128_CBC_SHA256",
           0x00FF: "RENEGOTIATION_SCSV"}

cs_name = lambda c: CIPHERS.get(c, hex(c))

for direction, data in streams.items():
    pkts = ip_packets(bytes(data))
    print(f"\n=== {direction}: {len(pkts)} UDP packets ===")
    for p in pkts:
        j = 0
        while j + 13 <= len(p):
            ctype = p[j]
            epoch = int.from_bytes(p[j + 3:j + 5], "big")
            ln = int.from_bytes(p[j + 11:j + 13], "big")
            body = p[j + 13:j + 13 + ln]
            j += 13 + ln
            if ctype == 0x14:
                print("  ChangeCipherSpec (encryption starts)")
            elif ctype == 0x17:
                print(f"  encrypted app data, {ln} bytes")
            elif ctype == 0x16 and epoch == 0 and len(body) >= 12:
                t = body[0]
                frag_off = int.from_bytes(body[6:9], "big")
                m = body[12:]
                print(f"  Handshake: {HS_TYPES.get(t, t)}")
                if frag_off:
                    continue
                if t == 1 and len(m) > 35:           # ClientHello
                    k = 34
                    k += 1 + m[k]                     # session id
                    k += 1 + m[k]                     # cookie
                    n = int.from_bytes(m[k:k + 2], "big")
                    suites = [int.from_bytes(m[k + 2 + x:k + 4 + x], "big")
                              for x in range(0, n, 2)]
                    print("    offered:", ", ".join(cs_name(s) for s in suites))
                if t == 2 and len(m) > 35:           # ServerHello
                    k = 34
                    k += 1 + m[k]                     # session id
                    print("    CHOSEN:", cs_name(int.from_bytes(m[k:k + 2], "big")))
            elif ctype == 0x16:
                print("  encrypted handshake (Finished)")
