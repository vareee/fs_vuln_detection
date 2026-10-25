# Testing

## Commands

Run the Rust test suite:

```bash
cargo test
```

Verify API restrictions that must fail at compile time:

```bash
cargo test --doc
```

Compare the diagnostic outcomes of the historical Python and revised Rust implementations:

```bash
venv/bin/python tests/compare_implementations.py
```

Measure coverage and enforce the project-wide line target:

```bash
cargo llvm-cov --all-targets --summary-only --fail-under-lines 75
```

Run performance and memory measurements:

```bash
cargo bench --bench transcript_benchmarks -- --noplot
bash scripts/measure_memory.sh
```

The coverage command requires `cargo-llvm-cov` and the `llvm-tools-preview`
component.

## Coverage targets

The targets apply to line coverage because it directly shows which implementation
paths were executed and is stable for the current Rust toolchain.

| Scope | Target | Measured | Status |
| --- | ---: | ---: | --- |
| Core mechanism in `transcript.rs` | 90% | 96.90% | reached |
| Entire Rust project | 75% | 85.92% | reached |

The project-wide result includes `main.rs`, which is a demonstration binary and
is not executed by `cargo test`. This makes the total result conservative.

The current detailed result was measured after compacting the journal's exact
submitted sets and latest-challenge summary, without changing the heuristic, using
`cargo llvm-cov --all-targets --offline --summary-only --fail-under-lines 75`:

| File | Regions | Functions | Lines |
| --- | ---: | ---: | ---: |
| `transcript.rs` | 96.42% | 97.42% | 96.90% |
| `weak_bulletproofs.rs` | 45.25% | 35.59% | 50.00% |
| `weak_shnorr.rs` | 68.27% | 15.31% | 63.37% |
| `main.rs` | 0.00% | 0.00% | 0.00% |
| Total | 83.25% | 59.74% | 85.92% |

The forged Bulletproof scenario is expected to stop at the first detected
transcript violation. Code after that violation is intentionally unreachable in
the negative test, which explains the lower coverage of that example.

The current suite contains 67 unit tests, 51 integration tests, 3
compile-fail documentation tests and 6 Python/Rust scenario comparisons.
Coverage percentages are the file-level figures reported by `cargo-llvm-cov`,
including executed inline unit tests; they are not a proof of protocol security.
The historical cross-round example intentionally differs: Python rejects an
early value with a later challenge, while Rust accepts it. The other five
scenario outcomes agree. The comparison script asserts both expected sets of
outcomes rather than silently requiring identical behaviour.

## Computation-origin tests

Origin recording and automatic dependency inference are tested together. They
cover:

- equal values registered independently, clone identity and fresh operation IDs
- ordered arithmetic operands and operation kinds, without transcript mutations
- response registration linked to the computation without relabelling old origins
- modulo, list indexing and explicitly untracked `modpow` parameters
- failure atomicity for the origin journal as well as transcript bytes
- dependencies derived from observed operations, without manual declarations
- several challenge origins in one round and poisoned-lock errors
- no origin records in `Disabled` and mode-equivalent arithmetic/challenges
- inspector moves, expired contexts, `Send`/`Sync` and scoped-thread arithmetic

The cross-round regression tests cover:

- later challenges applied to earlier inputs, without an exact-round requirement
- identical dependency propagation for addition, subtraction and multiplication
- stale challenges that do not cover newly submitted inputs
- neutral constants and fixed generators, without treating them as challenges
- source sets preserved across aliases, list indexing and inspector moves
- provenance from both modulo operands and known `modpow` base provenance
- independent equal-valued objects and unused operations that do not change aliases
- 32-round chains with fresh inputs in each round and 20,000-operation expressions
- several challenges in one round and later registration of challenge aliases
- immediate errors in both operand orders and all owned/borrowed operator forms
- journal, transcript, index and round atomicity after failed arithmetic
- symmetric read-only diagnostics, unknown labels and poisoned journal locks
- absent journals in `Disabled` and scoped-thread arithmetic in `Full`

`test_round_sets` retains an independent `HashSet` oracle for 4,096 combinations
of synthetic submitted/challenge summaries across four binary operation kinds.
It checks that the compact representation preserves both decisions and result
summaries, including different submitted sets with equal maximum rounds.
`test_submitted_rounds_union` checks all 256 pairs of subsets of
`[0, 2, 63, usize::MAX]` in both operand orders, including storage reuse, sorted
unique output and unchanged sources. `test_sparse_round_interaction` checks
the maximum-round boundary without incrementing or overflowing round indices.
`test_shared_origin_storage` verifies shared allocations through arithmetic,
response aliases, list indexing and `modpow`, with no allocations for empty sets.
`test_origin_layout` guards the reduction in the record's fixed-size storage.
These finite tests supplement the unbounded collection-based implementation;
32 or four rounds are test sizes, not protocol limits.

The memory probe also exercises a fixed-origin arithmetic chain and growing
multi-round dependencies. Its script checks both modes and supports
`CARGO_TARGET_DIR`; the measured before/after figures and remaining costs are
documented in `PERFORMANCE.md`.

Known heuristic boundaries have regression tests, not claims of vulnerability:

- an inner mixed expression can fail before an outer challenge is used, although
  a different evaluation structure is accepted
- a local response retains its known provenance; the same received value starts
  a fresh submitted origin without importing the prover's history
- a local response derived only from constants/challenges has an empty submitted
  set, unlike a received response, so the two paths can have different diagnostics
- arithmetic tags describe syntax, not nonzero semantic influence or resistance
  to algebraic cancellation

## Independent protocol checks

`tests/protocol_binding.rs` contains eight tests. The Schnorr fixture transfers
only public inputs and canonical proof bytes (compressed SEC1 commitment and a
32-byte scalar) between independent inspectors. It checks the actual Schnorr
equation, equal challenge/transcript bytes, equal results in `Full` and `Disabled`,
and rejection of changed responses, commitments, messages and public keys by the
verification equation. Malformed point/scalar encodings are rejected separately.
This deterministic fixture is not a production or BIP 340 implementation.

A separate test records a real false positive: a valid proof satisfies native
`sG == R + eP`, but the tracked residual `sG - (R + eP)` is suspicious because the
received response has a newer submitted round. `Full` still fails fast on this
heuristic finding; it does not replace verification or promise to accept every
correct protocol implementation.

The Bulletproof-shaped fixture exercises `A,S -> y,z -> T1,T2 -> x`, including
late commitments, `x*S`, a stale-challenge expression and an omitted late input
declaration. It is not a full range proof, a Dalek integration or Plonky3 PoC.
`used_names` audits the input declaration; all registered public bytes have
already entered the cumulative transcript regardless of that declaration.

## Test matrix

| Category | Scenario | Expected result | Representative test |
| --- | --- | --- | --- |
| Correct | Complete public protocol round | accepted | `public_api_supports_a_complete_protocol_round` |
| Correct | Multi-round dependency chain | accepted | `public_api_tracks_a_multi_round_dependency_chain` |
| Correct | Arbitrary number of rounds | accepted | `cross_round_check_supports_an_arbitrary_number_of_rounds` |
| Correct | Several challenges in one round | accepted | `several_challenges_can_belong_to_one_round` |
| Correct | Safe Schnorr transcript | accepted | `safe_ok` |
| Correct | Repeated response registration under distinct labels | preserved dependencies | `repeated_response_registration_preserves_dependencies` |
| Correct | Same protocol in `Full` and `Disabled` | identical challenges | `public_api_preserves_challenges_when_inspection_is_disabled` |
| API restriction | Public key after the first challenge | rejected | `transcript_err` |
| API restriction | Values from different checked transcripts | rejected | `test_cross_transcript_error` |
| Heuristic | Different submitted rounds without a challenge | suspicious | `test_cross_round_without_challenge` |
| Declaration error | Incomplete, unknown or repeated challenge input | rejected | `challenge_validation_reports_input_errors` |
| Heuristic | Unused multiplication cannot change an earlier result | suspicious | `later_multiplication_does_not_change_an_earlier_origin` |
| Heuristic | Early challenge followed by a later submitted input | suspicious | `an_earlier_challenge_does_not_cover_a_later_message` |
| Correct | Challenge added instead of multiplied | accepted by heuristic | `challenge_dependencies_do_not_require_multiplication` |
| Heuristic | Independent value equal to a challenge | no challenge provenance | `equal_values_do_not_share_challenge_identity` |
| Negative example | Forged Bulletproof transcript | declaration violation detected | `test_forged_bulletproofs` |
| Boundary | Empty protocol label | accepted | `empty_protocol_label_is_allowed` |
| Boundary | Empty or duplicate element label | rejected | `empty_element_label_is_rejected_without_mutation`, `repeated_element_label_is_rejected_without_mutation` |
| Boundary | Empty challenge batch | rejected | `empty_challenge_batch_and_invalid_order_are_rejected` |
| Boundary | Order less than two | rejected | `empty_challenge_batch_and_invalid_order_are_rejected` |
| Boundary | Different orders in one transcript | accepted | `challenges_can_use_different_orders_in_one_transcript` |
| Boundary | Different local names | identical challenge | `element_labels_do_not_change_challenge_values` |
| Boundary | Private prover constants | identical challenge | `private_constants_do_not_change_challenge_values` |
| Boundary | Different protocol labels | different challenge | `protocol_labels_separate_challenge_values` |
| Boundary | Failed operation followed by a valid one | unchanged later challenge | `failed_validation_does_not_change_a_later_challenge` |
| Boundary | Disabled inspection with invalid metadata | protocol continues | `disabled_mode_skips_security_checks` |
| Boundary | Structural error in disabled mode | rejected | `disabled_mode_keeps_structural_validation` |
| Boundary | Failed cross-round arithmetic | journal and transcript unchanged | `test_cross_round_arithmetic_atomicity` |
| Boundary | Late evaluation or repeated registration | original sets preserved | `test_origin_rounds` |
| Heuristic limit | Inner expression rejected before outer challenge use | immediate finding | `rejected_subexpressions_are_reported_before_outer_operations` |
| Protocol | Independent Schnorr verifier | valid equation accepted | `schnorr_proof_verifies_with_independent_inspectors` |
| Protocol | Tampered Schnorr proof or public input | equation fails | `schnorr_verifier_rejects_tampered_proof_and_public_inputs` |
| Heuristic limit | Valid Schnorr residual | known false positive | `valid_schnorr_equation_can_still_trigger_a_residual_warning` |

## Compile-time test matrix

| Invalid API usage | Expected result | Documented on |
| --- | --- | --- |
| Construct `TaggedValue` outside the crate | compilation error | `TaggedValue` |
| Combine `TaggedValue` with an untracked integer | compilation error | `TaggedValue` |
| Pass an untracked `Value` to local `add_response` | compilation error | `TranscriptInspector` |

External values intentionally enter through `add_received_response`; its
existence does not invalidate the local-response signature test.

## Deferred integration coverage

Plonky3 integration tests are deferred until the adapter and vulnerable scenario
are implemented. They will extend this matrix with a native correct proof flow,
an intentionally unsafe flow and equality checks for challenges with inspection
enabled and disabled.
