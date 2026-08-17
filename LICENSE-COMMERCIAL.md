# Commercial Licence

hiccup is published under the [Business Source License 1.1](LICENSE) (BSL 1.1).
The BSL 1.1 lets anyone read, modify, self-host and redistribute the source
code for **non-production use** — development, testing, evaluation, security
audit, academic research, teaching and personal study — without paying
anything.

**Production use requires a commercial licence.** In hiccup's case "production
use" means using it as part of running a real service or real paid work:
troubleshooting a live voice platform, analysing a customer's captures under a
support contract or SLA, or offering hiccup to third parties as a hosted,
managed or embedded service. The exact wording is in the
[Additional Use Grant](LICENSE) — that text governs, this page only explains
it.

This page explains how to obtain a licence.

---

## Why a commercial licence?

The BSL 1.1 model keeps the source code transparent and auditable — which
matters more than usual here, because hiccup ingests signalling traces
containing phone numbers, IP addressing and credentials. Your security team,
your DPO and your customers' procurement people can read every line that
touches their data. In exchange, the companies that derive commercial value
from the tool fund its development.

Each released version converts automatically to the **Apache License 2.0**
four years after release (Change Date `2030-08-17` for the current version).
After that date the version in question is fully permissive open-source
software with no commercial restrictions at all — so a commercial licensee is
protected against lock-in and against the project being abandoned.

---

## Who needs a commercial licence?

You need one if you intend to use hiccup (or any derivative work) for any of
the following:

- Troubleshooting, assuring, migrating or certifying a **live** voice,
  video or messaging service — your own or a customer's.
- Any trace analysis performed as part of paid work, a support contract, a
  managed service, a professional-services engagement or an SLA commitment.
- Hosting hiccup for use by colleagues, customers or any third party outside
  your immediate evaluation / development team.
- Embedding hiccup source or code into another product, appliance or service
  offered to third parties (including an SBC vendor's own tooling).
- Running hiccup as a managed or hosted service on behalf of others.

You do **not** need a commercial licence to:

- Read the source code.
- Run hiccup locally to evaluate it, including against your own captures.
- Have your security team, DPO or auditors review the code.
- Modify the source code for your own non-production experimentation.
- Use it for teaching, academic research, personal study, or a home lab.
- Submit patches, file issues, or otherwise contribute to the project.

If you are unsure which side of the line a particular use falls on, ask before
you deploy — the answer is usually cheap and always cheaper than the
alternative.

---

## How to obtain a commercial licence

Email **<licensing@rfplex.ai>** with:

1. **Organisation name** and primary contact.
2. **Intended use** — internal trunk troubleshooting? A NOC or support desk?
   Professional services for customers? Embedded in your own product? A short
   paragraph is fine.
3. **Approximate scale** — number of engineers who would use it, whether it
   is one team or org-wide, and which regions you operate in.
4. **Deployment model** — your own infrastructure, a private cloud, or a
   managed service.

You will receive a quote and a draft commercial licence agreement, typically
within 2–3 working days.

### Pricing (indicative, 2026)

Final pricing depends on scale, deployment and support requirements.
Indicative starting points:

| Tier                | Use case                                                              | From         |
| ------------------- | --------------------------------------------------------------------- | ------------ |
| **Single engineer** | One named engineer, internal use                                      | €240/yr      |
| **Team**            | One voice / NOC / support team, ≤10 engineers                         | €1,200/yr    |
| **Site**            | Multiple teams within one organisation, ≤50 engineers                  | €4,800/yr    |
| **Service provider**| Carrier, MSP or integrator using hiccup on customer traces            | from €12k/yr |
| **OEM / embed**     | Embedding hiccup in your own product or appliance                     | bespoke      |
| **Hosted re-sale**  | Offering hiccup as a service to your own customers                    | bespoke      |

The above are indicative — every commercial licence is bespoke. Public-sector,
academic and registered-charity rates are available on request.

---

## Frequently asked

**Can I evaluate it for free first?**
Yes — non-production evaluation is unrestricted under the BSL 1.1 itself, and
the Additional Use Grant says so explicitly. Read the source, run it on your
own hardware, point it at your own captures, get your security team to audit
it. No commercial licence required, no time limit, no feature gating.

**Is hiccup open source?**
No. It is **source-available**. You can read, build, modify and self-host it,
but the licence restricts production use for four years per version. See the
[Licence section of the README](README.md#licence).

**What happens after the Change Date (2030-08-17)?**
That version converts automatically to Apache License 2.0 — fully permissive,
no commercial restrictions. Versions released after that date get their own
four-year BSL 1.1 window.

**I am a one-person consultancy. Do I really need the service-provider tier?**
No. Ask — the single-engineer tier exists precisely for that case.

**Does the free beta of anything change this?**
hiccup is currently free while in beta, and beta users are not billed. That is
a commercial decision about the hosted beta, not a change to the source-code
licence: the terms in [LICENSE](LICENSE) still govern the code.

**What about contributions back to the project?**
Welcome. Contributors sign off via the Developer Certificate of Origin (DCO)
and grant the project the right to relicense their contributions, which means
contributing does **not** itself require a commercial licence.

**What if I have already been using hiccup in production without a licence?**
Email <licensing@rfplex.ai>. There is no penalty for coming forward and
regularising. A paying customer is a much better outcome for everyone than a
dispute.

---

*This document is informational and does not itself constitute a commercial
licence. The legally binding commercial licence agreement is a separate
document countersigned by both parties. Where this page and
[LICENSE](LICENSE) differ, LICENSE governs.*
