# Deploying netscan on your network

This document is about the decision that determines whether this project is
useful to you or not. Read the first section before touching any config.

## The thing nobody tells you: you cannot scan encrypted traffic

Somewhere between 90% and 98% of a typical home network's traffic is HTTPS or
QUIC. A scanner sitting between your router and the internet sees, for each of
those connections, a TLS handshake followed by encrypted bytes. Not a filename.
Not a MIME type. Not a file. Encrypted bytes.

This is not a limitation of netscan. It is what TLS is for, and it is the same
reason your ISP cannot see what you download. Any product claiming to "scan all
traffic from your router" is doing one of three things:

1. **Scanning only the small unencrypted remainder** — plain HTTP, FTP, old
   SMTP, SMB on the LAN. Real, but a minority of traffic.
2. **Intercepting TLS** — terminating every connection with its own
   certificate, which requires installing its CA on every device.
3. **Running an agent on each device** — scanning after decryption, on the
   endpoint. This is what commercial antivirus does.

There is no fourth option. Pick deliberately.

## Three deployments, and which one to actually use

### Passive tap (recommended starting point)

Zeek watches a copy of your traffic, carves out every file it can see, and
netscan scans each one. Nothing is inline, so a crashed scanner cannot take your
internet down and a slow scan cannot stall a download.

```
                 ┌──────────┐
  internet ──────┤  router  ├────── your devices
                 └────┬─────┘
                      │ mirror / SPAN port (a copy of the traffic)
                      ▼
                 ┌──────────┐    carved files     ┌─────────┐
                 │   Zeek   ├────────────────────►│ netscan │──► alerts, log,
                 └──────────┘  /var/log/zeek/     └────┬────┘    quarantine
                                 extract_files/        │
                                                  ┌────▼────┐
                                                  │  clamd  │
                                                  └─────────┘
```

- **Sees:** HTTP, FTP, SMTP, SMB, TFTP — anything unencrypted, in both
  directions, including LAN-internal transfers.
- **Cannot:** block anything, or see inside HTTPS.
- **Best at:** telling you a device on your network is already compromised. IoT
  malware, LAN-to-LAN spread, and plaintext C2 all show up here, and none of it
  is hidden by TLS.

Getting the traffic copy is the only hard part, and depends on your hardware:

| Your setup | How to get a copy of the traffic |
|---|---|
| Managed switch (even a cheap one) | Configure a SPAN/mirror port. Cleanest option. |
| OpenWrt on the router | `tcpdump`/`iptables TEE` to a monitor host, or run Zeek on the router if it has the RAM (it usually does not) |
| pfSense / OPNsense | Zeek and Suricata both available as packages — use those |
| Consumer router, unmanaged switch | You cannot mirror. Put the scanner box inline as a bridge instead (below) |

### Transparent bridge (passive, but inline hardware)

A box with two network interfaces, bridged, between router and switch. Zeek
watches the bridge. Same visibility as the tap, but no managed switch needed —
and if the box dies, your network dies with it unless you configure the bridge
to fail open.

### Inline proxy with ICAP (the only one that can block)

Squid terminates the connection, hands each response body to netscan over ICAP,
and netscan answers "pass" or "block".

```
                 ┌──────────┐                    ┌─────────┐
  your device ───┤  Squid   ├── ICAP RESPMOD ────┤ netscan │
                 └────┬─────┘   (blocks here)    └────┬────┘
                      │                          ┌────▼────┐
                 internet                        │  clamd  │
                                                 └─────────┘
```

- **Sees:** plain HTTP out of the box. HTTPS **only** with TLS interception.
- **Can:** actually stop a download, and show the user why.
- **Costs:** every response is buffered until a verdict exists, so downloads
  stall. Budget one worker per concurrent download.

#### If you enable TLS interception, know what you are signing up for

You generate a CA, install it as trusted on every device, and Squid
man-in-the-middles every connection. On your own network, with your own devices,
this is legitimate. It is also genuinely disruptive:

- **Certificate pinning breaks.** Banking apps, Windows Update, the App Store,
  WhatsApp, Signal, most mobile apps. Each needs an explicit bypass rule, and
  the failure mode looks like "the internet is broken", not "scanning blocked
  this".
- **QUIC bypasses you entirely.** Chrome and Firefox prefer HTTP/3 over UDP/443,
  which a TCP proxy never sees. You must block UDP/443 at the router to force
  browsers back to TCP, which slows down every site that supported QUIC.
- **Devices you cannot install a CA on are excluded.** Smart TVs, consoles, IoT
  — exactly the devices most likely to be compromised.
- **You now hold every plaintext session.** Your scanner box sees everyone's
  banking pages, passwords in transit, private messages. It becomes the most
  security-sensitive machine you own. If other people use this network, get their
  agreement first — this is not a technical detail.

**Recommendation:** run the passive tap permanently. Add the inline proxy only
if you have a specific need to block, and even then, start with plain HTTP only
and see whether the coverage justifies the interception before enabling it.

And regardless of which you pick: the highest-coverage, lowest-drama control is
still an endpoint scanner on each machine, because it runs after decryption.
Network scanning complements that; it does not replace it.

## Installation

### Passive path

```bash
# 1. Zeek on the monitoring host (Ubuntu/Debian)
sudo apt install zeek           # or build from https://zeek.org

# 2. Load the extraction script
echo '@load /opt/netscan/deploy/zeek/netscan-extract.zeek' \
  | sudo tee -a /opt/zeek/share/zeek/site/local.zeek

# 3. Point Zeek at the interface carrying the mirrored traffic
sudo zeekctl deploy

# 4. clamd, with signatures
sudo apt install clamav-daemon clamav-freshclam
sudo freshclam                  # ~250MB, takes a few minutes
sudo systemctl enable --now clamav-daemon

# 5. netscan
git clone <this repo> /opt/netscan && cd /opt/netscan
python3 -m venv .venv && .venv/bin/pip install -e '.[yara]'
.venv/bin/netscan status        # confirm every detector is ready
.venv/bin/netscan selftest      # confirm detection actually works

# 6. Run it
sudo cp deploy/systemd/netscan-watch.service /etc/systemd/system/
sudo systemctl enable --now netscan-watch
```

Or with Docker (Zeek still runs on the host):

```bash
docker compose -f deploy/docker-compose.yml up -d
```

### Inline path

```bash
sudo apt install squid
# Merge deploy/squid.conf into /etc/squid/squid.conf, then:
sudo cp deploy/systemd/netscan-icap.service /etc/systemd/system/
sudo systemctl enable --now netscan-icap squid
```

Redirect traffic to Squid at the router:

```bash
# On an OpenWrt router, 192.168.1.10 being the scanner host:
iptables -t nat -A PREROUTING -i br-lan -p tcp --dport 80 \
    -j DNAT --to-destination 192.168.1.10:3128
```

## Sizing

| Deployment | RAM | Notes |
|---|---|---|
| clamd alone | 2–3 GB | Signature database is resident; below 2GB it fails to start |
| + Zeek, 100 Mbit | 4 GB | Zeek is CPU-bound on packet reassembly |
| + Zeek, 1 Gbit | 8 GB, 4+ cores | Consider PF_RING or multiple Zeek workers |
| + Squid inline | +1 GB | Plus disk for buffering concurrent downloads |

A Raspberry Pi 4 (8GB) handles a passive tap on a typical home connection. A Pi
will not handle inline TLS interception at gigabit — that needs real x86.

**Disk is the thing that catches people out.** Extracted files accumulate fast.
netscan deletes clean files after scanning, but if the watcher stops while Zeek
keeps running, the disk fills within hours. Set a size limit on the extraction
directory and monitor it.

## Tuning out false positives

Run for a week and read the log before changing any thresholds:

```bash
# What is firing, most common first
jq -r '.findings[].rule' /var/log/netscan/scan.jsonl | sort | uniq -c | sort -rn

# Everything currently blocking
jq -r 'select(.verdict=="malicious") | "\(.name)\t\(.findings[0].rule)"' \
  /var/log/netscan/scan.jsonl

# Which hosts are involved
jq -r 'select(.verdict!="clean") | .meta.recipient' \
  /var/log/netscan/scan.jsonl | sort | uniq -c | sort -rn
```

Common sources of noise and what to do:

- **`risky_extension` on everything** — expected. It is `suspicious`, not
  `malicious`, and does not block at the default threshold. Use `--quiet` to
  stop it filling your console.
- **`office_macro_project` on internal documents** — legitimate if your
  workplace uses macros. Add those files' hashes to an allowlist.
- **`high_entropy_content` on installers** — self-extracting archives look
  packed because they are. Allowlist the specific vendors you trust.
- **`encrypted_archive_entry`** — only meaningful if you have decided
  password-protected archives are not normal on your network.

Never respond to noise by raising `block_at` to `suspicious` and then
allowlisting your way out. Start at `malicious`, which is deliberately
conservative, and only tighten once the log is quiet.

## What this does not do

Being explicit, because a scanner that you trust more than it deserves is worse
than no scanner:

- **It does not see encrypted traffic** unless you intercept TLS. Say it again.
- **It does not detect novel malware by behaviour.** No sandbox, no emulation.
  The structural checks catch delivery *tricks*, and ClamAV/YARA catch *known*
  code. A clean-looking novel binary passes.
- **It does not inspect RAR or 7-Zip contents.** Both need external tools; the
  container is flagged as uninspectable rather than silently passed. clamd will
  look inside them if built with support.
- **It does not stop anything in the passive deployment.** By design.
- **It cannot scan what it cannot decrypt or decompress** — password-protected
  archives are reported as `unknown`, not clean.
