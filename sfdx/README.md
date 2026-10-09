# Hiccup for Salesforce

Lets Salesforce process a customer ticket (Case) with Hiccup: a pcap or SBC
log attached to the Case is sent to Hiccup, which finds the fault and
suggests fixes; the diagnosis is posted back as a private Case comment.

```
Case + attached pcap/log
        │  Agentforce action / Flow / Apex
        ▼
HiccupCaseAnalyzer ──(Queueable)──► HiccupClient ──► POST {hiccup}/mcp  tools/call analyze_capture
        ▲                                                   │
        └──────── private CaseComment  ◄── findings + advice ┘
```

## Setup

1. **Hiccup:** on a Pro/Team account create an API token on `/settings`
   (`hk_...`).
2. **Named Credential `Hiccup`** (Setup > Named Credentials), URL
   `https://<your hiccup host>`. Authentication: an External Credential with a
   custom header `Authorization` = `Bearer hk_...`, and a Permission Set that
   grants the principal to whoever runs the action.
3. **Deploy:** `sf project deploy start --source-dir sfdx/force-app` (run the
   tests with `--test-level RunLocalTests`).
4. **Use it:**
   - *Agentforce:* add the invocable action **Analyse Case capture with
     Hiccup** to an agent topic (Agent Builder > Actions > Apex).
   - *Flow:* call the same action from a record-triggered flow, e.g. when a
     file is added to a Case.
   - *Apex:* `HiccupCaseAnalyzer.enqueue(caseId);`

## Two ways to connect

| Path | Use when | Auth |
| --- | --- | --- |
| Apex action (this folder) | You want the Case updated end to end today | Static bearer in a Named Credential, so no OAuth needed |
| Agentforce's native external-MCP registration | You want the agent to call Hiccup's tools directly (list findings, read a call) | OAuth 2.0 client credentials: token URL `https://<host>/oauth/token`, client secret = the `hk_` token |

The `/oauth/token` endpoint is a thin client-credentials wrapper over API
tokens: it validates the token and hands it back as the access token. It has
not been exercised against a real Agentforce org yet, so treat the native
registration as unverified until you try it. Salesforce's docs list OAuth
client credentials and no-auth for external MCP servers and do not mention a
static bearer header.

## Limits

- Files over 3 MB are refused with a Case comment (async Apex heap, base64
  growth). Trim the capture to the failing call.
- The newest `.pcap`, `.pcapng`, `.cap`, `.log` or `.txt` file on the Case is
  analysed. Numbers are masked in Hiccup's analysis by default.
- The Apex has not been compiled or run in an org from here; the tests in
  `HiccupCaseAnalyzerTest` mock the callout.
