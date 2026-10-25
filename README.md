## About

This project is aimed to create mechanism which can be used to find vulnerabilities in Fiat-Shamir transfromation implementations.

Main mechanism is being realised on Rust. 

MVP on Python is stored on python_proto dir.

The complete test matrix and current coverage measurements are documented in
[`TESTING.md`](TESTING.md).

The boundary between compile-time guarantees and dynamic protocol checks is
documented in [`COMPILE_TIME_CHECKS.md`](COMPILE_TIME_CHECKS.md).

The benchmark method, performance results and memory measurements are documented
in [`PERFORMANCE.md`](PERFORMANCE.md).

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

## Inspection modes

`TranscriptInspector::new` enables full inspection. An explicit mode can be
selected with `TranscriptInspector::with_mode`:

```rust
use fs_vuln_detection::{InspectionMode, TranscriptInspector};

let checked = TranscriptInspector::with_mode(
    b"application/protocol/v1/group",
    InspectionMode::Full
);
let unchecked = TranscriptInspector::with_mode(
    b"application/protocol/v1/group",
    InspectionMode::Disabled
);
```

`Full` enables Fiat-Shamir and cross-transcript checks, records arithmetic
origins, and applies a cross-round provenance heuristic immediately during
arithmetic. A suspicious pattern stops the operation, but is not by itself a
demonstration of a cryptographic vulnerability.
`Disabled` preserves transcript construction and challenge generation but skips
inspection checks. For an operation sequence accepted in both modes, arithmetic
values, transcript bytes and challenges are identical. A valid protocol can
still encounter a false positive from the heuristic in `Full`.

Structural validation remains enabled in both modes when it is required to
perform an operation safely. Examples include an empty or duplicate element
label, an empty challenge batch and an order less than two.

A separate diagnostic mode is intentionally not included. `Full` returns
`TranscriptError` values on the first failed check; accumulating and reporting
multiple findings remains a separate policy decision.

## Automatic computation origins and cross-round checks

`TaggedValue` remains the only public arithmetic wrapper. Its private
`origin_id` and weak connection identify a record in a journal owned by
`TranscriptInspector`. There is no `TrackedValue` or independent tracking graph.
Rounds, categories, labels and dependency summaries remain inside the inspector,
not in `TaggedValue`.

In `Full`, addition, subtraction, multiplication, modulo and list indexing record
their operation kind and operand origins automatically. Intermediate results do
not need labels, do not append transcript bytes and do not advance a round.
`clone()` preserves origin identity; independent registrations of equal values
have different identities. Registering a computed response creates a new event
pointing to the computation, without changing the original value or its clones.

The journal uses `Arc`/`Mutex` internally and values hold `Weak` connections.
Moving an inspector is supported, as is arithmetic on a scoped worker thread.
The inspector must stay alive while checked arithmetic is performed. If it has
been dropped, arithmetic returns `InspectionUnavailable` instead of silently
disabling inspection. A poisoned metadata lock returns `InspectionStatePoisoned`.

`Disabled` does not record origins and its values do not depend on the lifetime
of the inspector. A small empty journal owner is still allocated by the
inspector; disabling inspection is not a promise of zero allocation overhead.
Accepted arithmetic, transcript bytes and challenges remain identical between modes.

`add_response(label, response)` preserves the recorded computation; it no longer
takes a list of challenge names. The manual `record_challenge_multiplication`
method and its separate dependency map have been removed. For example, after
registering the public key and message and generating `e`:

```rust
let e_msg = (e * message)?;
let response = (public_key - e_msg)?;
transcript.add_response("response", response)?;
```

The `+`, `-`, `*` and `modulo` operations check their operands before appending a
journal record. A suspicious interaction returns
`TranscriptError::SuspiciousCrossRoundInteraction`, even if its result would
never be registered with `add_response`. This replaces the earlier
`UnsafeCrossRoundInteraction` diagnostic and its exact-round multiplication rule.
Failed operations do not modify the journal, transcript bytes or round counter.
The optional `check_cross_round_interaction` method applies the same heuristic
to registered operands without performing arithmetic. An unknown label returns
`UnknownElement`, not a cross-round finding.

### Round provenance policy

Each journal record describes two kinds of provenance, separate from the
cryptographic transcript:

- `submitted_rounds`: rounds of independently registered protocol inputs used by
  the computation, stored as an exact sorted set with shared immutable storage
- `latest_challenge`: the latest generation round of any challenge used by the
  computation, or `None` if no challenge has been observed

The earlier `challenge_rounds` set is summarized by its maximum because the
heuristic only uses that maximum. This does not discard information used by the
current check. Submitted rounds cannot be reduced to a maximum: the rule also
compares the complete sets for equality. For example, `{0, 2}` and `{1, 2}` are
different submitted sets even though their latest round is the same.

A fresh commitment, public key, message or received response contributes its
registration round to `submitted_rounds`. A generated challenge contributes its
generation round to `latest_challenge`, not the submitted rounds of every value
that was hashed. Constants and declared fixed protocol generators have an empty
submitted set and no observed challenge.

For two operands, the heuristic skips the round check if either submitted set is
empty or if the two submitted sets are equal. Otherwise the combined provenance
must satisfy:

```text
max(left.latest_challenge, right.latest_challenge) >= max(submitted_rounds)
```

If neither operand has an observed challenge, this condition fails. Otherwise
the comparison uses the latest available challenge round; `None` does not add a
round. Generation rounds are used because the cumulative transcript is hashed
through that round. The rule does not require a challenge from exactly the
original message round, and does not require a multiplication node. The policy
is based on the
[Origin Tags round-provenance diagnostic](https://github.com/AztecProtocol/aztec-packages/blob/c1b606f97dcd56668ccd8087a794190c34b4c571/barretenberg/cpp/src/barretenberg/transcript/origin_tag.cpp),
whose [documentation also describes legitimate false positives](https://barretenberg.aztec.network/api/namespacebb).
This is a diagnostic heuristic, not a general theorem about valid ZK protocols.

For example, let `m0` be submitted in round 0, `e0` generated at its end, `m1`
submitted in round 1 and `e1` generated after `m1`. Then:

```text
e1 * m0          allowed: a later challenge may be used with an early input
(e0 * m0) + m1   suspicious: e0 predates m1
(e1 * m0) + m1   allowed by the heuristic
```

`e0 * m1` alone is also accepted because one operand contains only challenge
provenance. This deliberate scope means that the checker diagnoses mixing of
submitted data, not every use of an early challenge with a later input.

Successful `+`, `-`, `*` and `modulo` operations union the exact submitted sets
and take the maximum of the observed challenge rounds from both operands,
including the modulus for `modulo`. Multiplication has no special privilege.
List indexing inherits the list's provenance. `modpow` retains the known
provenance of its base, but its raw exponent and modulus remain untracked.
Clones and local response aliases preserve both summaries. An independently
registered number equal to a challenge is not tagged as a challenge; an unused
operation does not update another value's provenance. Several challenges from
one logical round have distinct origin identities and the same generation-round
tag.

When a union is already represented by either operand's submitted set, the
result shares that immutable storage instead of allocating a copy. A union
that adds rounds to both operands creates a new sorted set. This sharing and
the maximum-only challenge summary are internal storage optimizations: they do
not change the public API, operation identities, transcript bytes or the
heuristic's decisions. The journal still retains a record of each successful
tracked operation until the inspector is dropped. It is not a bounded-memory
trace: many distinct growing submitted sets can still require memory
proportional to the number of records times their round counts. See
`PERFORMANCE.md` for measurements and remaining costs.

The check supports arbitrary round counts. Evaluating an old expression later
does not change its origin, and `add_response` does not reclassify old data as a
fresh submission. A rejected subexpression cannot be repaired by a later outer
operation: `e1 * (m0 + m1)` fails at `m0 + m1`, although `(e1 * m0) + m1` is
accepted. This expression-order sensitivity is another limitation of immediate
syntactic checking, not a claim that the first mathematical expression is unsafe.

Commitments may be registered in later rounds; they must still appear in the
next challenge's input declaration. The existing restriction on registering
public keys after the first challenge remains an API limitation, not a universal
requirement of zero-knowledge protocols. `used_names` audits a declaration of
challenge inputs; it does not select which already serialized bytes are hashed
or declare arithmetic provenance.

### External responses and trust boundaries

`add_received_response(label, value)` registers an external response as a fresh
input of the current round. It returns an ordinary `TaggedValue` and does not
invent challenge dependencies or accept a prover-supplied computation journal.
In contrast, `add_response(label, response)` accepts a locally computed
`TaggedValue` and preserves its known provenance. Neither method proves that a
response satisfies the protocol's verification equation.

A local response computed only from constants and challenges has no submitted
rounds, even after `add_response`. The same value received by another process
gets a submitted-round tag through `add_received_response`. The heuristic can
therefore produce different diagnostics on the two sides despite identical
transcript bytes. It observes local data flow, not a shared proof of provenance.

`add_generator` declares a fixed protocol parameter, neutral to round provenance
but still serialized and subject to the existing first-challenge checks. The
caller must validate that parameter according to the protocol. A fresh
prover-selected input must not be relabelled as a generator or constant to bypass
inspection. Participant names alone do not establish trust. Constants remain
excluded from transcript bytes; generators do not.

A separate verifier does not need the prover's computation history. For example,
it can register a received Schnorr response `s`, compute `sG` using a fixed `G`,
compute `R + eP`, and compare the two native group values. The independent
prover/verifier tests in `tests/protocol_binding.rs` transfer only public inputs
and canonical proof bytes. They verify an actual Schnorr equation, reject
tampered proofs and public inputs, and check transcript agreement; they are not
a BIP 340 implementation or a production-ready proof system.

Even here, computing the residual `sG - (R + eP)` through tracked arithmetic
triggers a known false positive: `s` arrived after `e` and introduces a newer
submitted round. A regression test preserves this limitation explicitly. The
native equality check verifies the proof; the provenance heuristic does not
analyze or replace that equation. General protocol adapters still need a policy
for dependencies established by verification relations, not just local syntax.

Raw `Value`/`BigInt`/point extraction leaves the tracked computation boundary.
Re-registering a raw value cannot recover its previous computation. Algebraic
normalization, cancellation, multiplication by zero and semantic influence are
not analyzed: a challenge tag can survive even when its numerical contribution
does not. Both false positives and missed vulnerabilities are possible.
Accepting an operation never proves cryptographic security, just as a suspicious
finding is not a proof of exploitability.

The existing integer serializer reduces values modulo the secp256k1 base-field
modulus before encoding. Challenge hashing binds those encoded representatives,
not arbitrary distinct `BigInt` values: integers differing by that modulus have
the same encoding. This pre-existing encoding limitation is not changed by the
provenance policy and must be addressed in adapters for other value domains.

The Bulletproof-shaped regression fixture covers the ordering `A,S -> y,z ->
T1,T2 -> x` and a late challenge multiplying an early commitment. It also checks
an intentionally stale-challenge expression and an incomplete input declaration.
It is not a complete Bulletproof implementation, an integration with Dalek, or
the planned Plonky3 proof of concept.

Challenge batches are prepared before committing origin records, keeping failed
metadata access from partially modifying the cryptographic transcript. This
uses a temporary copy of the transcript; previous performance measurements need
to be repeated after the provenance migration and the new round-provenance policy.

## Python and Rust scenario comparison

The Python prototype is retained as a historical reference. Five reference
scenarios retain their previous outcome; the old cross-round example now has an
intentional policy difference:

| Scenario | Python | Rust |
| --- | --- | --- |
| Safe Schnorr transcript | accepted | accepted |
| Public key added after the first challenge | detected | detected |
| Cross-transcript interaction | detected | detected |
| Historical cross-round example | rejected by old rule | accepted by revised heuristic |
| Interaction with an untracked operand | detected | detected |
| Incomplete Bulletproof transcript | detected | detected |

That example uses a later challenge with an earlier value; this is not by itself
an invalid Fiat-Shamir interaction. Its previous rejection is not retained as a
security requirement. The comparison script checks all six scenarios, including
this expected difference. Diagnostic text may also differ. Run it with:

```bash
venv/bin/python tests/compare_implementations.py
```
