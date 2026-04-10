# Security Policy

## A note up front

HermitStash is a personal project maintained by one person in their spare time. It uses well-regarded post-quantum cryptographic primitives from established libraries, but the code has not been professionally audited. I'm a developer, not a cryptographer, and there are almost certainly things I've gotten wrong that I don't yet know are wrong.

If you're evaluating HermitStash for a use case where the consequences of a security flaw matter — legal, medical, financial, journalistic, or anything else where being wrong has real stakes — please factor this into your decision.

## Reporting a vulnerability

If you find a security issue, **please do not open a public GitHub issue**. Public disclosure before a fix is in place puts users at risk.

Instead, please email me directly:

**security@hermitstash.com**

### What to include

A useful report usually has:

- A clear description of the issue
- Steps to reproduce, or a proof of concept
- The version or commit hash you tested against
- Your assessment of the impact (what could an attacker actually do?)
- Any suggested fix, if you have one

Don't worry about formatting it perfectly. I'd rather get a rough report than no report.

## What to expect from me

I want to be honest about response times: this is a side project, and I can't promise the kind of turnaround a funded security team would offer. Realistically:

- **Acknowledgment:** within a few days, usually faster
- **Initial assessment:** within a week or two
- **Fix and disclosure:** depends on severity and complexity

For critical issues (anything that breaks the core security promises — confidentiality of stored files, integrity of encrypted data, authentication bypass), I'll prioritize and try to ship a fix as quickly as I reasonably can. For lower-severity issues, it may take longer.

I'll keep you updated as I work on it, and I'll credit you in the fix commit and release notes unless you'd prefer to stay anonymous.

## Scope

Things I consider in scope:

- Cryptographic flaws (misuse of primitives, weak key derivation, nonce reuse, etc.)
- Authentication and session bypass
- Authorization issues (accessing files or data you shouldn't)
- Data exposure (plaintext leaking somewhere it shouldn't)
- Server-side request forgery, injection, or path traversal
- Anything that contradicts a security claim made in the README

Things that are probably out of scope:

- Issues in dependencies that are already publicly known and have updates available — please open a normal issue for these
- Theoretical attacks that require capabilities beyond a realistic threat model
- Self-XSS or social engineering attacks against the user
- Anything that requires already-compromised admin credentials

If you're not sure whether something is in scope, just send it. I'd rather decide together than have you not report something that matters.

## What I can't offer

To set expectations honestly:

- No bug bounty. I can't pay for findings — this is a personal project with no budget. I can offer credit, gratitude, and a genuine attempt to fix what you find.
- No SLA. I'll do my best, but I can't guarantee response times.
- No guarantees about backwards compatibility while I'm fixing things. If a fix requires breaking changes, I'll make them.

## Thank you

Security research is real work, and reporting issues responsibly takes time and care. If you take the time to look at HermitStash and tell me what you find, you have my genuine thanks — even if the finding turns out to be a false alarm or out of scope.
