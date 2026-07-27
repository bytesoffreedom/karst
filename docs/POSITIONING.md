# KARST positioning guide

The single source of truth for how KARST is described in public. Every README,
website page, social profile, video, and announcement must conform to this
document and must not exceed [`SECURITY_CLAIMS.md`](SECURITY_CLAIMS.md).

---

## Canonical descriptions

**Short (EN):**
> Experimental open-source private messenger with end-to-end encryption and hybrid post-quantum key agreement. Built in Rust around independently operated relays.

**Short (RU):**
> Экспериментальный мессенджер с открытым исходным кодом, сквозным шифрованием и гибридной постквантовой защитой.

**Extended (EN):**
> KARST is an experimental open-source private messenger. It uses end-to-end encryption, a hybrid key agreement combining post-quantum and classical cryptography, and independently operated relays. The project is designed to give users control over their cryptographic identity and reduce dependence on a single service provider.

**Product line (EN / RU):**
> Private messaging built for long-term confidentiality.
> Защищённая переписка с расчётом на долгосрочную конфиденциальность.

---

## The four pillars

1. **Protection from unauthorized access** — end-to-end encryption protects message content from unauthorized third parties and compromised relay infrastructure.
2. **Protection against identity substitution** — safety-number verification helps users detect substitution of a contact's cryptographic identity.
3. **Protection against data breaches** — relays store encrypted envelopes rather than plaintext conversations, reducing the consequences of a server compromise.
4. **Long-term confidentiality** — hybrid post-quantum key agreement is intended to reduce harvest-now-decrypt-later risk. The construction remains experimental and independently unaudited.

---

## Primary security narrative

KARST is positioned as protection against unauthorized third parties,
cybercrime, infrastructure compromise, account theft, data breaches,
identity substitution, and long-term interception risk.

**The public narrative must not identify governments, law-enforcement
agencies, regulators, or political groups as the project's primary
adversaries.**

The technical threat model remains **actor-neutral**: security properties
apply based on an adversary's capabilities and actions, not their identity
or affiliation.

> Describe adversaries by capability, not by political or institutional identity.

Use:
- `an observer able to see both network endpoints`
- `a compromised relay operator`
- `an attacker controlling a network path`
- `an unauthorized party with access to a device`
- `an attacker recording encrypted traffic for future analysis`

Do not use:
- `a government watching the user`
- `law enforcement trying to identify users`
- `a censor attempting to suppress communication`

---

## Allowed statements

- Protects message content from unauthorized access.
- Reduces the amount of trust placed in relay operators.
- Helps protect conversations on untrusted networks.
- Helps detect contact-key substitution through safety-number verification.
- Keeps local message history encrypted at rest.
- Reduces the consequences of a compromised relay.
- Uses hybrid post-quantum key agreement to address long-term interception risk.
- Does not require a phone number for cryptographic identity.
- Gives users control over their cryptographic identity.
- Uses independently operated relays to reduce dependence on one service provider.
- Designed with data breaches and infrastructure compromise in mind.
- Open source and available for independent security review.

## Prohibited statements

Never use, even as a headline, meme, or quote without critical framing:

- quantum-proof; quantum-safe (unqualified); unbreakable; unhackable;
- impossible to decrypt / intercept / block; guaranteed post-quantum security;
- fully / completely anonymous; untraceable; leaves no trace;
- protects against the state / law enforcement / intelligence services;
- no one can compel / sue / seize / shut down the project;
- no legal entity, therefore invulnerable;
- censorship-resistant; anti-censorship; unblockable; DPI-evading;
- "recording ciphertext buys nothing"; "looks like ordinary HTTPS";
- "no signature of its own"; "indistinguishable from ordinary traffic";
- защищает от государства / властей / спецслужб; невозможно взломать / расшифровать / заблокировать / отследить; полная анонимность; гарантированная защита от квантовых атак.

Do not use the bare word **"hacker"** (it includes legitimate security
researchers). Prefer: malicious actors, cybercriminals, unauthorized
attackers, operators of malware, compromised infrastructure.

---

## Post-quantum wording

Allowed:
> KARST uses a hybrid key agreement combining ML-KEM-768 and X25519, followed by a Double Ratchet.
> The design is intended to reduce harvest-now-decrypt-later risk.
> Hybrid post-quantum protection is enabled in the reference implementation.
> The cryptographic composition is experimental and has not been independently audited.

Always keep this caveat available near any post-quantum claim:
> Reference implementation. The cryptographic composition has not been independently audited.

---

## Standard warnings

**Repository / release:**
> Experimental pre-alpha. Independently unaudited. Not for high-risk communications.

**Feature announcement tail:**
> The implementation remains experimental and unaudited.

---

## Templates

### Feature post

1. What is implemented.
2. What user or engineering problem it solves.
3. What the mechanism guarantees.
4. What it does not guarantee.
5. Audit status.
6. Link to the PR or commit.

> KARST now supports WebSocket over TLS as an optional transport adapter. This expands interoperability with standard TLS infrastructure. It does not guarantee browser-level traffic indistinguishability, anonymity, or universal connectivity. The implementation remains experimental and unaudited.

### Release announcement

> KARST <version> — experimental open-source private messenger with end-to-end encryption and hybrid post-quantum key agreement. <one-line summary of changes>. Experimental pre-alpha, independently unaudited; not for high-risk communications. Source: <link>. Verify: <SHA256SUMS / signature>.

### Telegram post

> <Feature name>. <What shipped, in plain terms>. <What real-world risk it reduces>. <What it does not guarantee>. <Audit status, if crypto/metadata>. PR/commit: <link>.
>
> Never use fear, state confrontation, or a promise of invulnerability as a hook.

### Video description

> KARST — experimental open-source private messenger. End-to-end encryption, hybrid post-quantum key agreement, independently operated relays. Experimental and unaudited; not for high-risk use. Source and security model: <links>.

### Social bio

> Open-source private messenger with end-to-end encryption and hybrid post-quantum key agreement. Experimental and unaudited.

---

## Final canonical statement

> KARST is an experimental open-source private messenger with end-to-end encryption and hybrid post-quantum key agreement. It is designed to reduce the risks of unauthorized access, account and infrastructure compromise, identity substitution, data breaches, and long-term interception of encrypted traffic. It does not guarantee anonymity, absolute security, or protection against every adversary.
