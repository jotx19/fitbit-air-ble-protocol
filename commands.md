# Commands used

Every command below runs inside a disposable Ubuntu container. Nothing is
installed on the Mac except Docker.

## 1. Start the container (Mac folder mounted at /work)

```bash
cd ~/fitbit-research
docker run -it -v "$PWD":/work -w /work ubuntu:24.04 bash
```

## 2. Install tools (inside the container)

```bash
apt-get update && apt-get install -y tshark python3
```

## 3. Unpack the sysdiagnose and grab the Bluetooth log

```bash
tar -xzf sysdiagnose_*.tar.gz
cp ./sysdiagnose_*/logs/Bluetooth/bluetoothd-hci-latest.pklg bt.pklg
```

## 4. Sanity-check the capture

```bash
# time range + packet count
capinfos bt.pklg | grep -i -E "first|last|packets"

# confirm TShark can read it
tshark -r bt.pklg | head -20
```

## 5. Identify the devices

```bash
# device names seen per connection handle
tshark -r bt.pklg -Y "btatt.device_name" \
  -T fields -e bthci_acl.chandle -e btatt.device_name 2>/dev/null | sort -u

# how much ATT traffic per connection (busiest = the band)
tshark -r bt.pklg -Y "btatt" \
  -T fields -e bthci_acl.chandle 2>/dev/null | sort | uniq -c

# services exposed per connection (look for 0x180D Heart Rate)
tshark -r bt.pklg -Y "btatt.uuid16 || btatt.uuid128" \
  -T fields -e bthci_acl.chandle -e btatt.uuid16 -e btatt.uuid128 2>/dev/null | sort -u
```

The band here was connection handle `0x0040`. Adjust the handle below if yours differs.

## 6. Look at what the phone wrote to the band

```bash
tshark -r bt.pklg -Y "bthci_acl.chandle == 0x0040 && (btatt.opcode == 0x12 || btatt.opcode == 0x52)" \
  -T fields -e frame.time -e btatt.handle -e btatt.value 2>/dev/null | head -40
```

This is where the `45 00 ... 11 ... a9fe0002 a9fe0003 1634 ...` (IPv4/UDP/CoAP-DTLS)
structure becomes visible.

## 7. Export all band traffic for the Python parser

```bash
tshark -r bt.pklg -Y "bthci_acl.chandle == 0x0040 && btatt.value" \
  -T fields -e frame.number -e btatt.opcode -e btatt.value 2>/dev/null > att.tsv
```

## 8. Parse the DTLS handshake

```bash
python3 analyze.py
```

Prints the offered/chosen cipher suites per direction.

## Cleanup

```bash
exit   # leave and discard the container
```

Then remove Apple's Bluetooth logging profile on the iPhone:
**Settings → General → VPN & Device Management**.
