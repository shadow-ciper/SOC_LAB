# 🔎 Wireshark Filters Reference — PsExec Hunt Lab

A complete reference of all Wireshark display filters used in this investigation, with explanations of what each filter targets and why it's useful.

---

## SMB Connection Filters

### Identify SMB Connection Initiators
```
tcp.flags.syn == 1 && tcp.port == 445
```
**What it does:** Shows only TCP SYN packets (connection initiation) on port 445 (SMB).  
**Why useful:** In a large PCAP, this instantly isolates hosts that *initiated* SMB connections rather than receiving them — pointing directly to the attacker or lateral movement source.

---

### All SMB2 Traffic
```
smb2
```
**What it does:** Shows all SMB2 (Server Message Block version 2) packets.  
**Why useful:** Broad filter for initial SMB analysis before narrowing down by command.

---

## SMB2 Command Code Filters

SMB2 uses numeric command codes to identify packet types. Key codes:

| Code | Command | Use Case |
|------|---------|---------|
| `0` | Negotiate | Protocol version negotiation |
| `1` | Session Setup | Authentication — reveals usernames and hostnames |
| `2` | Logoff | Session termination |
| `3` | Tree Connect | Share connection — reveals share names (ADMIN$, IPC$) |
| `5` | Create/Open | File operations — reveals filenames being accessed or written |

### Session Setup (Authentication)
```
smb2.cmd == 1
```
**What it does:** Shows all SMB2 Session Setup packets — the authentication handshake.  
**Why useful:** These packets contain NTLM negotiation data including target hostnames and usernames.

### Tree Connect (Share Access)
```
smb2.cmd == 3
```
**What it does:** Shows all SMB2 Tree Connect packets — when a client connects to a share.  
**Why useful:** Reveals exactly which share path is being accessed (e.g., `\\10.0.0.133\ADMIN$`).

### File Create/Open
```
smb2.cmd == 5
```
**What it does:** Shows all SMB2 file creation and open requests.  
**Why useful:** Used to detect files being dropped on remote machines.

### Specific Filename Filter
```
smb2.cmd == 5 && smb2.filename == "PSEXESVC.exe"
```
**What it does:** Filters file operations specifically for PSEXESVC.exe.  
**Why useful:** Direct detection of PsExec binary being written to a target.

---

## NTLM Authentication Filters

### All Authentication Attempts (Username Visible)
```
ntlmssp.auth.username
```
**What it does:** Shows only NTLMSSP_AUTH (Type 3) packets — the final authentication message containing the submitted username.  
**Why useful:** Extracts usernames from authentication attempts without needing to crack any hashes.

### Successful Authentications Only
```
smb2.cmd == 1 && smb2.flags.response == 1 && smb2.nt_status == 0x00000000
```
**What it does:** Filters Session Setup *responses* (server side) with NT Status = SUCCESS.  
**Why useful:** Distinguishes successful logins from failed attempts.

### Common NT Status Codes
| Code | Meaning |
|------|---------|
| `0x00000000` | ✅ Success (NT_STATUS_OK) |
| `0xC000006D` | ❌ Wrong username or password |
| `0xC000006E` | ❌ Account restriction |
| `0xC0000064` | ❌ User does not exist |

### NTLM Server Challenge (Hostname Extraction)
```
ntlmssp.challenge.target_name
```
**What it does:** Shows NTLMSSP_CHALLENGE (Type 2) packets — the server's authentication response.  
**Why useful:** The Target Name field in this packet contains the *server's hostname* in plaintext — extremely useful for mapping internal machine names without endpoint access.

---

## NTLM Message Types Reference

| Type | Name | Direction | Contains |
|------|------|-----------|---------|
| Type 1 | NTLMSSP_NEGOTIATE | Client → Server | Supported capabilities |
| Type 2 | NTLMSSP_CHALLENGE | Server → Client | Server hostname, challenge value |
| Type 3 | NTLMSSP_AUTH | Client → Server | Username, domain, hashed credentials |

---

## Host Discovery Filters

### NetBIOS Name Service
```
nbns
```
**What it does:** Shows NetBIOS Name Service broadcasts.  
**Why useful:** Windows machines constantly broadcast their hostnames via NBNS — a passive way to map IP → hostname without touching the endpoints.

### LLMNR (Link-Local Multicast Name Resolution)
```
llmnr
```
**What it does:** Shows LLMNR name resolution traffic.  
**Why useful:** Similar to NBNS, used by modern Windows machines for local name resolution — hostnames visible in plaintext.

---

## DCERPC Filters (Remote Service Installation)

### All DCERPC Traffic
```
dcerpc
```
**What it does:** Shows Distributed Computing Environment / Remote Procedure Call traffic.  
**Why useful:** PsExec uses DCERPC to communicate with the Service Control Manager (SCM) remotely.

### CreateService RPC Call
```
dcerpc.cmd == 12
```
**What it does:** Filters for the CreateService RPC operation specifically.  
**Why useful:** Direct detection of remote service creation — the core mechanism of PsExec and many other lateral movement tools.

---

## Combined Investigation Workflow

```
Step 1 — Find attacker IP:
tcp.flags.syn == 1 && tcp.port == 445

Step 2 — Find first pivot hostname:
smb2.cmd == 1
→ Look for NTLMSSP_CHALLENGE → Target Name

Step 3 — Find attacker username:
ntlmssp.auth.username
→ Look for NTLMSSP_AUTH → User name field

Step 4 — Confirm PsExec deployment:
smb2.cmd == 5 && smb2.filename == "PSEXESVC.exe"

Step 5 — Find shares used:
smb2.cmd == 3
→ ADMIN$ = file delivery | IPC$ = SCM communication

Step 6 — Find second pivot hostname:
ntlmssp.challenge.target_name
→ Look for new Target Name values from internal IPs
```
