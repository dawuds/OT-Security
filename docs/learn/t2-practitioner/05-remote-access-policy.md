# Lab — Draft a remote-access policy from the template

> **Tier 2 / Lesson 5 — 90 minutes.** Produce a real document.

## Why this lab

In every audit, the auditor will ask: "show me your remote access policy". If you don't have one, that's a finding. If you have a generic IT one, that's still a finding because it doesn't account for vendor access, jump-server protocol breaks, JIT, or operator override.

You are going to produce one. Real, signed off — at least defensible enough that the next auditor accepts it as a baseline.

## What you start with

- The template: [`08-identity-access-management-policy`](#templates/view:08-identity-access-management-policy) — read it once before customising.
- The framework: B.A.S.I.C. S.T.A.R.T. Pillar 6 — [Secure Remote Access](#basic-start/pillar-secure-remote-access) — for the principles.
- The requirements: [Remote Access Management domain](#framework/domain:remote-access).
- The control: [Remote access management](#controls) (filter to the domain `remote-access`).

## What you must add to the template

The IT-flavoured template covers MFA, RBAC, password policy. For OT, you must extend it with these sections — none of which the IT template handles:

1. **Vendor remote access** — explicit JIT (just-in-time) provisioning, time-bounded sessions, per-vendor scope (Vendor A → only their PLCs).
2. **Jump server protocol break** — the user's laptop never has a routable path to Level 0–3. Session terminates in the IDMZ; new session opens from there.
3. **Operator override / sovereignty** — the on-shift operator can kill any remote session immediately. Specify the mechanism (HMI workflow, physical key-switch, or both).
4. **Session recording** — for vendor sessions, full video; for internal, command logging at minimum. Storage in IDMZ, retention 90 days.
5. **Banned tools** — explicit list of tools that are *not allowed* for OT remote access (TeamViewer, AnyDesk, raw RDP from corporate, etc.). Outbound to these from OT is monitored and alerts.
6. **MFA in plant constraints** — most plants ban mobile phones on the floor. YubiKey or equivalent hardware token is the practical answer.
7. **NACSA s20 alignment** — the policy must reference Act 854 s20 (incident management capability) — disconnect-from-IT authority must be named, not implied.

## The deliverable

A `remote-access-policy.md` (or .docx) file with all seven additions above, customised to your plant. Audience: the people who will sign it — typically Plant Manager, IT Director, OT Manager, CISO.

Length test: if your policy is shorter than 4 pages, you've under-specified. If longer than 12, you've over-specified.

## What "good" looks like

- Every clause cites the IEC 62443 SR or NACSA section it satisfies.
- The "approved tools" list is short and named.
- The "operator override" workflow has a named operator role and a named system mechanism.
- The "session recording" clause specifies storage location and retention.
- The "vendor onboarding" section names the form, the approval chain, and the JIT credential issuance method.

## What "bad" looks like

- Generic phrases: "appropriate access controls", "secure remote access", "industry-standard authentication". These mean nothing.
- No vendor section at all.
- "MFA via SMS" — phone bans on the plant floor make this unworkable; SMS is also weak.
- No operator override.

For a worked example of *exactly what bad looks like*, read [`docs/learn/samples/03-bad-remote-access-policy.md`](../samples/03-bad-remote-access-policy.md). It is structured to *appear* compliant. Identify the six failures (the [answer key](../samples/05-answer-key.md) lists them). If your draft has any of those six failures, rewrite the affected section.

## What's next

[Checkpoint](#learn/lesson:t2-practitioner:06-checkpoint) — review the five deliverables you should now own.
