# Reverse Engineering the Google Fitbit Air's Bluetooth Protocol

> Captured and analyzed using only an iPhone and Docker — no jailbreak, no root, no special hardware.

## TL;DR

I wanted to know if I could make the Google Fitbit Air (a screenless $99 fitness band) buzz its vibration motor for phone notifications, a feature Google doesn't offer. To find out, I captured the Bluetooth traffic between the band and the official Google Health app and worked out how it talks.

It turns out the Fitbit Air doesn't use a simple Bluetooth command protocol. It runs a **full miniature network stack over Bluetooth Low Energy**: IPv4 → UDP → CoAP → DTLS 1.2, secured with a pre-shared key. Adding custom features would require extracting that key from the app, which is locked away on an unmodified phone.

This repo documents how I captured and decoded it, start to finish.

## The question

The Fitbit Air has a vibration motor, but Google only uses it for silent alarms and a low-battery buzz, not for call/message notifications. The motor is right there. Could a custom app trigger it?

To answer that, I needed to see how the official app sends commands to the band.

## The tools

- An **iPhone** paired with the Fitbit Air (no jailbreak)
- A **MacBook** running **Docker** (nothing else installed on the host)
- Inside a throwaway Ubuntu container: **TShark** (Wireshark CLI) and **Python 3**

The whole point was to keep the Mac clean. All analysis happened inside a disposable Linux container.

## Step 1 — Capture Bluetooth traffic from the iPhone

iOS can log Bluetooth internally, no Mac capture tools needed:

1. Installed Apple's **Bluetooth logging profile** (from `developer.apple.com/bug-reporting/profiles-and-logs`) and restarted.
2. In Google Health, set an alarm on the band and changed the vibration intensity a few times.
3. Triggered a **sysdiagnose** (Volume Up + Volume Down + Side button).
4. AirDropped the resulting archive to the Mac.

The Bluetooth log lives inside the archive at:

```
logs/Bluetooth/bluetoothd-hci-latest.pklg
```

## Step 2 — Analyze inside Docker

```bash
cd ~/fitbit-research
docker run -it -v "$PWD":/work -w /work ubuntu:24.04 bash

# inside the container
apt-get update && apt-get install -y tshark python3
tar -xzf sysdiagnose_*.tar.gz
cp ./sysdiagnose_*/logs/Bluetooth/bluetoothd-hci-latest.pklg bt.pklg
```

### Find the band

The band was already connected, so it wasn't advertising its name. I identified it by its active connection and the services it exposed:

```bash
tshark -r bt.pklg -Y "btatt.device_name" \
  -T fields -e bthci_acl.chandle -e btatt.device_name 2>/dev/null | sort -u
```

```
0x0040   Google Fitbit Air
0x0047   Bedroom
0x0048   jotxmac
```

Connection `0x0040` is the band. It exposes the standard **Heart Rate** service (`0x180D`) plus many custom 128-bit services — a classic fitness-tracker fingerprint.

## Step 3 — The surprise: it's a network stack

Dumping the ATT writes to the band revealed payloads that start with `45 00 ...`:

```
45 00 ... 11 ... a9fe0002 a9fe0003 1634 1634 ... 16 fefd ...
```

Decoded byte by byte:

| Bytes | Meaning |
|---|---|
| `45 00` | IPv4 header |
| `11` | Protocol = UDP |
| `a9fe0002` → `a9fe0003` | `169.254.0.2` → `169.254.0.3` (link-local addresses for phone & band) |
| `1634` | Port 5684 — **CoAP over DTLS** |
| `16 fefd` | DTLS 1.2 handshake record |
| `17 fefd` | DTLS 1.2 encrypted application data |

So the band and phone each act like a tiny computer with its own IP address, talking **CoAP** (a lightweight web protocol for embedded devices) inside an encrypted **DTLS 1.2** tunnel, all carried over Bluetooth LE.

## Step 4 — Inspect the DTLS handshake

A Python script reassembles the fragmented BLE writes back into UDP packets and parses the DTLS handshake (see [`analyze.py`](analyze.py)).

Key findings:

- **The band initiates the secure session.** It sends the `ClientHello`; the phone acts as the DTLS server. (Unusual — normally the phone would drive this.)
- **Chosen cipher suite: `TLS_PSK_WITH_AES_128_CCM`** — a **pre-shared key**, no certificates.
- The band also offered an `ECDHE_PSK` suite, but the phone selected plain PSK.

```
=== band->phone ===
  Handshake: ClientHello
    offered: PSK_AES_128_CCM, PSK_AES_128_GCM_SHA256, ECDHE_PSK_AES_128_CBC_SHA256
  ...

=== phone->band ===
  Handshake: ServerHello
    CHOSEN: PSK_AES_128_CCM
```

## What this means

1. **Everything rides on one pre-shared key**, agreed during initial pairing and stored by both the band and the Google Health app (iOS Keychain / Android Keystore).
2. **No forward secrecy.** Plain PSK (not ECDHE-PSK) means anyone who ever recovered the key could decrypt past captures too — a minor design weakness.
3. **Custom features are gated on that key.** To make the band do anything, you'd need to extract the PSK from the app — not possible on a stock iPhone, and even on a rooted Android phone the key may live in a non-exportable hardware keystore.

So: the vibration motor is reachable only by whoever holds the pairing key, which the OS deliberately protects. A custom notification feature isn't practical, and definitely isn't shippable to other users (each would need to extract their own key).

## What I took away

Even without decrypting a single command, the capture revealed the full architecture:

```
Bluetooth LE  →  IPv4  →  UDP  →  CoAP  →  DTLS 1.2 (PSK AES-128-CCM)
```

Running a real IP + CoAP + DTLS stack over BLE on a 5-gram, screenless, 7-day-battery device is a genuinely interesting engineering choice — it lets Google reuse standard, well-audited internet protocols instead of inventing a custom one.

## Files

- `analyze.py` — reassembles BLE writes into UDP packets and parses the DTLS handshake
- `commands.md` — the exact TShark/Docker commands used

## Legal note

This was interoperability research on my own device and my own data. No DRM was circumvented and no keys were extracted. Fitbit and Google are trademarks of their respective owners.
