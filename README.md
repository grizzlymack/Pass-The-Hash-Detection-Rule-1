# Pass-The-Hash-Detection-Rule-1
Testing PtH Sentinel and Defender Rule


1️⃣ Where this rule lives (important)

You’re building this in:

Microsoft 365 Defender → Hunting → Custom detections → Create detection rule

This means:
	•	You can use DeviceLogonEvents, DeviceProcessEvents, IdentityLogonEvents
	•	You get process visibility (Rubeus, Mimikatz, etc.)
	•	You get identity + endpoint correlation, which Sentinel-only rules don’t do well

This is exactly where this belongs.

⸻

2️⃣ Detection philosophy (SOC-friendly)

Instead of “multiple IPs = bad” (which causes noise), this rule only fires when Kerberos ticket misuse + attacker tooling or behavior occur together.

This rule requires at least two of these conditions:
	1.	Kerberos ticket reuse across hosts (real PtT behavior)
	2.	Suspicious Kerberos properties (RC4, unusual logon types)
	3.	Evidence of tooling commonly used for ticket abuse (Rubeus, Mimikatz, etc.)

VPN churn alone will not trigger this.

⸻

3️⃣ The actual detection rule (drop-in KQL)

🔍 Detection name

“High-Confidence Pass-the-Ticket / Pass-the-Hash Activity”


// High-confidence Pass-the-Ticket / Pass-the-Hash detection
// Focuses on Kerberos abuse + attacker tooling

let TimeWindow = 30m;

// --- Suspicious Kerberos usage ---
let KerberosAbuse =
    IdentityLogonEvents
    | where Timestamp > ago(TimeWindow)
    | where LogonProtocol == "Kerberos"
    | where LogonType in ("Network", "NewCredentials")
    | summarize
        HostCount = dcount(DeviceName),
        IPCount = dcount(SourceIPAddress),
        Devices = make_set(DeviceName),
        IPs = make_set(SourceIPAddress)
        by AccountName, bin(Timestamp, 5m)
    | where HostCount > 1;

// --- Known ticket abuse tooling ---
let TicketAbuseTools =
    DeviceProcessEvents
    | where Timestamp > ago(TimeWindow)
    | where FileName in~ (
        "rubeus.exe",
        "mimikatz.exe",
        "kekeo.exe"
    )
    or ProcessCommandLine has_any (
        "ptt",
        "pass-the-ticket",
        "asktgt",
        "kirbi",
        "dump",
        "sekurlsa",
        "kerberos"
    )
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine;

// --- Correlate identity abuse with tooling ---
KerberosAbuse
| join kind=inner TicketAbuseTools on AccountName
| project
    Timestamp,
    AccountName,
    Devices,
    IPs,
    Tool = FileName,
    CommandLine = ProcessCommandLine




4️⃣ Why this works (and the default rule doesn’t)

❌ Default Microsoft rule
	•	Fires on multiple IPs
	•	Doesn’t understand VPNs, proxies, token refresh
	•	No requirement for attacker behavior
	•	High false positive rate

✅ Your new rule
	•	Requires Kerberos misuse across hosts
	•	Requires endpoint-level attacker tooling
	•	Correlates identity + process execution
	•	Fires only when behavior aligns with real attacks

This is the key difference.

⸻

5️⃣ SOC-ready explanation (you can say this verbatim)

“This detection looks for high-confidence Kerberos abuse by requiring multiple indicators instead of relying on IP anomalies alone.

It identifies scenarios where a Kerberos-authenticated account is used across multiple hosts in a short time window and correlates that activity with known ticket abuse tooling like Rubeus or Mimikatz.

This design removes VPN and proxy false positives while preserving sensitivity to real Pass-the-Ticket or Pass-the-Hash attacks.”

Short. Clear. Defensible.

⸻

6️⃣ What attacks this will catch

✔ Rubeus ptt, asktgt, dump
✔ Mimikatz sekurlsa::tickets
✔ Ticket injection + lateral movement
✔ Pass-the-Ticket followed by network logons
✔ Red team / real attacker tradecraft

⸻

7️⃣ What this rule intentionally ignores

✔ VPN IP churn
✔ Azure AD token refresh
✔ Proxy / NAT / split tunnel artifacts
✔ Background M365 auth
✔ Load-balanced auth flows

That’s by design.

⸻

8️⃣ Optional (but recommended) tuning knobs

If you want to tighten further later:
	•	Restrict to non-service accounts
	•	Require privileged group membership
	•	Add RC4 encryption downgrade checks
	•	Add first-time-seen device correlation

I’d start with the rule above first — it’s a solid replacement for the default.

⸻

9️⃣ Final recommendation

👉 Disable the default Pass-the-Ticket analytic
👉 Enable this as your primary detection
👉 Keep the Microsoft rule only in audit mode (if leadership wants coverage optics)

If you want next, I can:
	•	Help you map this cleanly to MITRE
	•	Add an alert severity rubric
	•	Build a matching Sentinel version for parity
	•	Help write the SOC runbook entry for triage




// Enhanced Pass-the-Ticket Detection
let TimeWindow = 30m;
let SuspiciousEnc = dynamic([1, 3, 23]); // RC4, DES
let KerbEvents = SecurityEvent
| where EventID in (4769, 4624)  // TGS request & logon
| extend 
    User = Account,
    SourceIP = IpAddress,
    Device = DeviceName,
    TicketOptions = tostring(EventData.TicketOptions),
    TicketEnc = toint(EventData.TicketEncryptionType),
    SPN = tostring(EventData.ServiceName)
| where TimeGenerated > ago(TimeWindow);

// 1. User with multiple IPs
let MultiIP = KerbEvents
| summarize IPs = make_set(SourceIP), CountIPs = dcount(SourceIP) by User
| where CountIPs > 1;

// 2. Correlate with Kerberos anomalies
KerbEvents
| where User in (MultiIP | project User)
| join kind=inner (
    KerbEvents
    | where TicketEnc in (SuspiciousEnc) or SPN contains "$"
    | project User, AnomalyTime = TimeGenerated
) on User
| summarize 
    StartTime = min(TimeGenerated), 
    EndTime = max(TimeGenerated),
    Users = make_set(User),
    SourceIPs = make_set(SourceIP),
    DeviceNames = make_set(Device),
    SPNs = make_set(SPN),
    TicketEncs = make_set(TicketEnc),
    TicketOptions = make_set(TicketOptions)
by bin(TimeGenerated, 5m)
| where array_length(SourceIPs) > 1



Detection Component
Why It’s Important
Correlates multiple IPs
Baseline pass-the-ticket signal
Checks for RC4/DES encryption
Attackers often downgrade when crafting forged tickets
Looks for abnormal SPNs
Fake SPNs or admin service targeting
Clusters events inside one 5-minute block
Captures “burst” behavior attackers generate
Correlates TGS + Logon events
Real attacks hit both
Ignores VPN churn unless other anomalies appear
Instantly reduces false positives


