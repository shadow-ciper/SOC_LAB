# SOC_LAB

Detection exercises and incident writeups. Everything here is reconstructed from
captured or supplied evidence — pcaps and phishing emails — with the analysis
written up step by step.

## What is in here

| Path | What it is |
|---|---|
| `WRITEUP.md` | PsExec lateral movement investigation, 40,294-packet pcap, with the seven questions answered and the reasoning shown |
| `WIRESHARK_FILTERS.md` | Every display filter used in that investigation, with an explanation of what each one isolates |
| `Sample1.png` … `Sample7.png` | Packet captures backing each answer |
| `phishing/` | 10 phishing email samples and the analysis of the first one |

## The PsExec hunt

An attacker reached a corporate network, authenticated over SMB/NTLM, and moved
laterally with PsExec. The chain, reconstructed from traffic alone:

```
Attacker (10.0.0.130)
  SMB/445  ->  SALES-PC (10.0.0.133)
    authenticated as ssales (credential sourced from HR-PC)
    PSEXESVC.exe dropped via ADMIN$ share
  ->  MARKETING-PC via IPC$ then ADMIN$
```

Techniques covered: SMB2 analysis, NTLM authentication flow, NetBIOS name
resolution for hostname identification, PsExec detection, and attack-chain
reconstruction from raw packets.

## The phishing set

Ten `.eml` files spanning credential harvesting, brand impersonation
(PayPal, Microsoft, Amazon, DocuSign, Dropbox, Office 365), an internal HR lure,
a bank fraud attempt, a CEO fraud BEC, and a multi-stage ransomware lure. These
are the standard commercial phishing-emulation categories, written to be
defensible in a SOC context.

The first is analysed in `phishing/REPORTS/email_01_basic_reports`, following the
structure in `phishing_playbook.txt` — sender spoofing, the Tor exit node in the
link, and user-report detection.

## Honest limitations

- **Lab material.** The pspec hunt is a CyberDefenders exercise, not a real
  incident. Lab pcaps are clean by construction; real ones are not.
- **Only 1 of 10 phishing emails is written up.** The other nine are samples with
  no analysis attached.
- **No tooling.** These are writeups and manual Wireshark filters. No detection
  rules, no automation — that gap is what
  [threat-hunter-toolkit](https://github.com/shadow-ciper/threat-hunter-toolkit)
  was built to close.