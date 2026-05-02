# 📝 Investigation Writeup — PsExec Hunt

**Lab:** PsExec Hunt | CyberDefenders  
**Analyst:** ShadowCiper  
**Date:** May 2026  

---

## Overview

This writeup documents a network forensics investigation of a PsExec-based lateral movement attack. A PCAP file of 40,294 packets was analyzed using Wireshark to reconstruct the full attack chain — from initial external access through lateral movement across multiple internal machines.

---

## Question 1 — Attacker's Initial Access IP

**Question:** What is the IP address of the machine from which the attacker initially gained access?

**Answer:** `10.0.0.130`

**Method:**

The PCAP contained over 40,000 packets — far too many to inspect manually. Since the attack involved SMB (a common lateral movement protocol on Windows networks), the investigation began by isolating all TCP SYN packets directed at port 445 (SMB):

```
tcp.flags.syn == 1 && tcp.port == 445
```

This filter reduced the visible packets to only those initiating SMB connections. Only one external host — `10.0.0.130` — was observed sending SYN packets to internal machines on port 445, confirming it as the attacker's machine.

**Screenshot:** `screenshots/Sample1.png`

---

## Question 2 — First Pivot Machine Hostname

**Question:** What is the hostname of the machine the attacker first pivoted to?

**Answer:** `SALES-PC`

**Method:**

Since the attacker communicated over SMB, the next step was to examine SMB2 Session Setup packets — the point where a client authenticates and identifies itself to a server:

```
smb2.cmd == 1
```

In the packet details pane, expanding the NTLM Secure Service Provider section revealed the **Target Name** field inside an `NTLMSSP_CHALLENGE` message. This field contains the hostname of the machine being connected to.

The packet from `10.0.0.133` (responding to `10.0.0.130`) showed:

```
Target Name: SALES-PC
```

This confirmed that `10.0.0.133` is `SALES-PC` — the first machine the attacker accessed.

**Screenshot:** `screenshots/Sample2.png`

**Protocol Note — NTLMSSP_CHALLENGE (Message Type 2):**  
This is the server's response to an authentication request. It contains the server's identity (Target Name/hostname) and a cryptographic challenge the client must respond to. The hostname is embedded here in plaintext.

---

## Question 3 — Attacker's Username

**Question:** What username did the attacker use for authentication?

**Answer:** `ssales`

**Method:**

To extract credentials from the traffic, the NTLM authentication messages were filtered directly:

```
ntlmssp.auth.username
```

This surfaces only `NTLMSSP_AUTH` packets (Message Type 3) — the final authentication message where the client submits its credentials. Expanding the NTLM fields on a packet from `10.0.0.130` revealed:

```
User name: ssales
Host name: HR-PC
Domain name: NULL
```

The attacker authenticated using the account `ssales`, operating from a machine called `HR-PC`.

**Screenshot:** `screenshots/Sample3.png`

**Protocol Note — NTLMSSP_AUTH (Message Type 3):**  
This is the client's response to the server's challenge. It contains the username, domain, host, and the hashed credential response. No plaintext passwords are transmitted — only hashed values.

---

## Question 4 — PsExec Service Executable Name

**Question:** What is the name of the service executable the attacker set up on the target?

**Answer:** `PSEXESVC.exe`

**Method:**

PsExec works by dropping a service binary onto the target machine via SMB. To find this, SMB2 file creation events were filtered while specifically searching for the PsExec binary name:

```
smb2.cmd == 5 && smb2.filename == "PSEXESVC.exe"
```

`smb2.cmd == 5` represents the **Create/Open** command — the operation used to write files over SMB. The results showed `PSEXESVC.exe` being written to the target, along with a `GetInfo` request querying the file's metadata — consistent with PsExec's standard installation sequence.

**Screenshot:** `screenshots/Sample6.png`

---

## Question 5 — Share Used to Install the Service

**Question:** Which network share was used by PsExec to install the service?

**Answer:** `ADMIN$`

**Method:**

To identify which share was used for file delivery, SMB2 Tree Connect packets were filtered — these are the packets where a client connects to a specific network share:

```
smb2.cmd == 3
```

Examining the Tree Connect Request from `10.0.0.130` to `10.0.0.133` revealed:

```
Tree: \\10.0.0.133\ADMIN$
```

`ADMIN$` is a Windows administrative share that maps to `C:\Windows`. PsExec uses this share to drop `PSEXESVC.exe` into the Windows directory on the target machine.

**Screenshot:** `screenshots/Sample7.png`

---

## Question 6 — Share Used for Communication

**Question:** Which network share did PsExec use for communication?

**Answer:** `IPC$`

**Method:**

Using the same `smb2.cmd == 3` filter, a second Tree Connect packet from `10.0.0.130` showed:

```
Tree: \\10.0.0.133\IPC$
```

`IPC$` (Inter-Process Communication share) is used by PsExec to communicate with the **Service Control Manager (SCM)** on the target — registering and starting the PSEXESVC service after the binary has been dropped via `ADMIN$`.

**PsExec Full Workflow:**
1. Connect to `IPC$` → authenticate via SCM
2. Connect to `ADMIN$` → drop `PSEXESVC.exe`
3. Return to `IPC$` → register and start the service via RPC

**Screenshot:** `screenshots/Sample4.png`

---

## Question 7 — Second Pivot Machine Hostname

**Question:** What is the hostname of the second machine the attacker pivoted to?

**Answer:** `MARKETING-PC`

**Method:**

Having established that the attacker moved from `10.0.0.130` → `SALES-PC (10.0.0.133)`, the next step was to check whether `SALES-PC` itself initiated further SMB connections — indicating a second pivot.

The filter used was:

```
ntlmssp.challenge.target_name
```

This surfaces NTLM Challenge messages (Type 2) — where servers identify themselves. Among the results, a packet from `10.0.0.131` revealed:

```
NetBIOS Domain Name: MARKETING-PC
NetBIOS Computer Name: MARKETING-PC
```

This confirmed that `10.0.0.131` is `MARKETING-PC` — the second machine in the attacker's lateral movement chain.

**Screenshot:** `screenshots/Sample5.png`

---

## Full Attack Chain

```
[Attacker]
10.0.0.130 (External)
    │
    │ 1. SYN to port 445 — SMB connection initiated
    │ 2. NTLM Auth as user: ssales (from HR-PC)
    ▼
SALES-PC — 10.0.0.133
    │ 3. PsExec: connects to ADMIN$ — drops PSEXESVC.exe
    │ 4. PsExec: connects to IPC$ — starts service via SCM
    │
    │ Lateral Movement
    ▼
MARKETING-PC — 10.0.0.131
    │ 5. PsExec repeated
    ▼
    [Further activity...]
```

---

## Key Lessons

1. **SYN + Port 445 filtering** is the fastest way to identify SMB-initiating hosts in large PCAPs.
2. **NTLMSSP_CHALLENGE (Type 2)** reveals the server's hostname — useful for mapping internal machines without endpoint access.
3. **NTLMSSP_AUTH (Type 3)** exposes the username and source hostname — even without cracking the hash.
4. **PsExec always uses two shares** — ADMIN$ for delivery, IPC$ for command execution. Both will appear in Tree Connect packets.
5. **smb2.cmd codes** are essential Wireshark filters for SMB analysis: `1` = Session Setup, `3` = Tree Connect, `5` = Create/Open file.
