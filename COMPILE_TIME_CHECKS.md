# Compile-time and runtime checks

The mechanism deliberately keeps one public arithmetic wrapper,
`TaggedValue`. It does not introduce nested wrappers for rounds, dependency
nodes or challenge kinds.

Computation tracking uses a private origin identifier and a weak connection
to the inspector-owned journal. The wrapper still contains no round or dependency
set. These private fields cannot be forged through the external API.

## Properties checked at compile time

- external code cannot construct `TaggedValue` directly
- external code cannot read or replace `TaggedValue::transcript_id`
- external code cannot mutate the wrapped `Value` without consuming the
  `TaggedValue`
- `add_response` accepts a locally computed `TaggedValue`, not an untracked
  `Value`; external inputs use the explicit `add_received_response` method
- tracked arithmetic accepts only `TaggedValue` operands
- object categories and low-level transcript insertion are inaccessible from
  the public API
- the chosen hash implementation must implement `FSHash`

The three `compile_fail` examples in the API documentation verify rejection of
external construction, arithmetic with a raw integer and raw `Value` insertion
through `add_response` during `cargo test --doc`. The remaining privacy
restrictions follow from the field and method visibility in the implementation.

## Properties checked at runtime

- two operands belong to the same transcript instance
- the variants stored in `Value` support the requested arithmetic operation
- labels are present, unique and refer to registered elements
- the challenge order is greater than one
- the first challenge contains the required public data
- all prover messages are included in challenge generation
- tracked operations satisfy the selected round-provenance heuristic
- the context for checked arithmetic is still alive and its metadata lock is
  usable

Cross-round checks use an exact sorted submitted-round set and the latest
observed challenge round in the inspector-owned journal. The submitted sets
have shared immutable storage; the challenge summary is `Option<usize>` rather
than a set because only its maximum is used by the current policy. If both
operands contain submitted inputs and their submitted-round sets differ, the
combined latest challenge round must be at least the latest submitted round.
Otherwise the round heuristic permits the operation. Equality still compares
the complete submitted sets, not just their maximum. These storage choices do
not change the check's decisions. This replaces the former exact-round
multiplication criterion; multiplication is not privileged over addition or
subtraction.

Registration through `add_response(label, response)` preserves the known local
computation without an additional challenge list. `add_received_response` instead
creates a fresh submitted input without claiming any challenge history.
The `+`, `-`, `*` and `modulo` operations apply the heuristic before recording
the result, including for unregistered intermediate values. They union both
operands' submitted sets and retain the maximum observed challenge round. When
the submitted union equals an operand's set, its immutable storage is reused.
Operation records themselves are retained for the inspector's lifetime; this
optimization does not remove the computation history or make memory use
independent of the number of operations and rounds.
`check_cross_round_interaction` is an optional
read-only diagnostic, not a required enforcement checkpoint. Unknown labels
produce `UnknownElement`; heuristic findings produce
`SuspiciousCrossRoundInteraction`.

Fixed validated generators are neutral to round provenance but remain hashed;
their fixed-parameter role is a caller contract, not a property proven by the
Rust type system. Constants remain un-hashed. Commitments may be registered in
later rounds and must be declared in the next challenge. The retained ban on
late public-key registration is a current API restriction, not a general ZK rule.

The checker does not normalize algebraic expressions or prove that a dependency
survives cancellation or multiplication by zero. `modpow` preserves the known
base provenance, while its raw exponent and modulus are outside the journal.
Immediate checks are expression-order sensitive and can reject mathematically
valid expressions. In particular, an independently received Schnorr response
can be verified by comparing `sG` and `R + eP`, without any prover history, yet
the tracked subtraction `sG - (R + eP)` still raises a heuristic false positive.
Neither a successful heuristic check nor a diagnostic establishes the proof's
cryptographic validity. The full rules and limitations are described in
`README.md`.

Semantic correctness of the protocol label, group, supplied order and encoding
must be established by the integrator; the current runtime checks do not infer
these protocol-specific properties.

These properties depend on values, protocol flow or dynamically registered
elements and therefore cannot be inferred from the current Rust types.

## Separate challenge types

A separate `ScalarChallenge` would prove only that a value was returned by a
scalar challenge operation. With the current API it would have to wrap
`TaggedValue`, adding another layer and conversions to every arithmetic
expression. It would not statically prove transcript identity, round safety,
challenge completeness or correctness of the supplied order.

A generic `TaggedValue<Role>` could avoid nested wrappers, but it would spread
role parameters through all arithmetic results. The correct result role often
depends on protocol semantics rather than on the algebraic operation alone, so
this design would require annotations from the user and would complicate
integration.

Base-field, extension-field and bit challenges should not be modelled as
integers with artificial moduli. Their types and sampling rules must come from
the integrated proof system. They will be evaluated against Plonky3 in the PoC
instead of being guessed in the standalone mechanism.

## Typestate evaluation

Typestate is not used for transcript rounds. The mechanism must support an
arbitrary number of rounds, several challenges in one round and protocol shapes
known only at runtime. Encoding every state transition in the type system would
replace the current single `TranscriptInspector` with multiple state types and
would make integration substantially more invasive.

The selected boundary is therefore:

- Rust privacy and method signatures prevent forging tracked values and bypassing
  the public registration API
- `TranscriptInspector` dynamically validates transcript identity, supported
  category restrictions and challenge declarations, and diagnoses suspicious
  round-provenance patterns
- native challenge types are reconsidered at the Plonky3 adapter boundary

This boundary preserves the original mechanism and its dynamic-analysis purpose
without introducing additional ownership layers.

Raw value extraction and subsequent external computation are outside the origin
journal. Re-registering the raw value cannot recover its previous computation.
The crate's own implementation remains trusted: some value fields and low-level
constructors are crate-visible for its demonstration code.
