# 🔍 Network Forensics Lab — PsExec Hunt (CyberDefenders)

**Platform:** CyberDefenders  
**Category:** Network Forensics  
**Tools Used:** Wireshark  
**Difficulty:** Medium  
**Status:** ✅ Solved

---

## 📌 Scenario

A PCAP file containing over 40,000 packets was provided. The goal was to trace an attacker who gained unauthorized access to a corporate network, moved laterally using PsExec over SMB, and compromised multiple internal machines — all reconstructed purely from network traffic.

---

## 🗂️ Repository Structure

```
.
├── README.md               ← You are here
├── writeup/
│   └── WRITEUP.md          ← Full step-by-step investigation writeup
├── filters/
│   └── WIRESHARK_FILTERS.md ← All Wireshark filters used with explanations
└── screenshots/
    ├── Sample1.png          ← Q1: Initial SMB SYN packets from attacker
    ├── Sample2.png          ← Q2: SMB2 Session Setup - SALES-PC hostname
    ├── Sample3.png          ← Q3: NTLMSSP_AUTH - username ssales, host HR-PC
    ├── Sample4.png          ← Q5/Q6: Tree Connect - IPC$ share
    ├── Sample5.png          ← Q7: NTLM challenge - MARKETING-PC hostname
    ├── Sample6.png          ← Q4: PSEXESVC.exe file creation
    └── Sample7.png          ← Q5: Tree Connect - ADMIN$ share
```

---

## 🧠 Key Concepts Demonstrated

- SMB/SMB2 protocol analysis
- NTLM authentication flow and field extraction
- PsExec lateral movement detection
- NetBIOS name resolution for hostname identification
- Wireshark display filter construction
- Attack chain reconstruction from raw PCAP

---

## ⚡ Attack Chain Summary

```
Attacker (10.0.0.130)
        │
        │ SMB Port 445 — Initial Access
        ▼
    SALES-PC (10.0.0.133)
        │ Authenticated as user: ssales (from HR-PC)
        │ PsExec: ADMIN$ → dropped PSEXESVC.exe
        │ IPC$ → SCM communication
        │
        │ Lateral Movement
        ▼
    MARKETING-PC (10.0.0.131)
        │ PsExec repeated
        ▼
    [Further Compromise]
```

---

## 🛠️ Tools

| Tool | Purpose |
|------|---------|
| Wireshark | Primary PCAP analysis and packet filtering |

---

## 📚 References

- [CyberDefenders](https://cyberdefenders.org)
- [Wireshark SMB2 Display Filters](https://www.wireshark.org/docs/dfref/s/smb2.html)
- [Microsoft NTLM Authentication Protocol](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm)
- [PsExec — Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
