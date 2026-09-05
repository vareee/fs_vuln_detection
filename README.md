## About

This project is aimed to create mechanism which can be used to find vulnerabilities in Fiat-Shamir transfromation implementations.

Main mechanism is being realised on Rust. 

MVP on Python is stored on python_proto dir.

## Challenge generation

`TranscriptInspector::record_challenge` creates a scalar Fiat-Shamir challenge as
`H(transcript) mod order`. The order is supplied for each generation operation
because one transcript may contain challenges for different groups. It is not
stored as a property of the transcript.

Element and challenge names are internal identifiers of `TranscriptInspector`.
They are not included in the hash, so a prover and verifier may use different
local names for corresponding protocol values. Owners and object categories are
also inspection metadata and are not serialized into the cryptographic
transcript.

Values registered as `Constant` are not included in the cryptographic transcript.
This allows the prover to track secret scalars without requiring the verifier to
know them. Public values and generated challenges are serialized in operation
order, so every challenge extraction advances the transcript state.

`TranscriptInspector::record_challenges` creates several scalar challenges in one
logical round. All challenges in that batch use the same order. Challenges with
different orders are created by separate calls.

This API deliberately describes scalar challenges only. An extension-field
challenge or a bit challenge must be sampled according to the native protocol
rules instead of being represented as an integer modulo an artificial order. The
Plonky3 proof of concept will define that adapter at the integration boundary.

## Protocol domain separation

The recommended protocol label format is:

```text
application/protocol/version/group-or-field
```

For example:

```text
fs-vuln-detection/schnorr/v1/secp256k1
fs-vuln-detection/bulletproof/v1/toy-modp
```

The label identifies a protocol suite, not a single transcript instance. Two
executions of the same protocol version over the same group use the same label.
A different protocol, incompatible protocol version, group, field or transcript
encoding uses a different label.

The group order alone is not a sufficient group identifier: different groups can
have the same order while using different element encodings or protocol rules.
For that reason `order` remains an argument of challenge generation and is not a
replacement for the group or field component of the protocol label.

An empty protocol label is accepted for compatibility. It should only be used
when the integrating protocol already performs equivalent domain separation
outside `TranscriptInspector`.

Challenge labels such as `y`, `z` and `x` identify elements in the dependency
graph but do not affect challenge values. Challenge calls are separated by the
evolving transcript state, while different protocols are separated by the
protocol label.

## Python and Rust scenario comparison

The Python prototype and the Rust implementation are expected to produce the
same security outcome for the reference scenarios:

| Scenario | Python | Rust |
| --- | --- | --- |
| Safe Schnorr transcript | safe | safe |
| Public key added after the first challenge | detected | detected |
| Cross-transcript interaction | detected | detected |
| Cross-round interaction | detected | detected |
| Interaction with an untracked operand | detected | detected |
| Incomplete Bulletproof transcript | detected | detected |

The exact diagnostic text may differ because the Rust version uses more precise
error variants. The outcomes can be checked automatically with:

```bash
venv/bin/python tests/compare_implementations.py
```
