# Performance measurements

## Current journal optimization

The comparison in this section uses the same round-provenance policy, public API
and operation history before and after optimizing its internal storage. It was
measured with Rust 1.95.0 on 64-bit Linux in the release profile. It is separate
from the older, pre-origin-tracking baseline retained later in this document.

`ValueOrigin` previously contained two `HashSet<usize>` fields. It now stores:

- `submitted_rounds: Option<Arc<[usize]>>`, an exact sorted unique nonempty set,
  or `None` for the empty set
- `latest_challenge: Option<usize>`, the maximum observed challenge round

Empty submitted sets allocate nothing. A union that equals either operand's set
reuses its immutable allocation; a genuinely new union is produced by a sorted
merge. Local response aliases, list indexing and `modpow` share the known input
set. There is no global interner, second graph or new public wrapper. The exact
set equality rule is preserved; challenge provenance may be summarized by its
maximum because no current check depends on the discarded intermediate rounds.

On this build `size_of::<ValueOrigin>()` decreased from 144 to 80 bytes. These
figures exclude dynamic set/string storage and spare vector capacity.
`TaggedValue` remains unchanged at 168 bytes. All operation records remain in
the journal until the inspector is destroyed.

### Memory comparison

The allocator probe measures requested live heap bytes and their peak within
each scenario, not process RSS or allocator bookkeeping. The table compares
peak bytes for identical fixtures with `Full` enabled; `Disabled` is an unchanged
reference, not native unwrapped arithmetic. `Full` includes the journal, retained
challenge-input sets and all other active validation metadata.

| Scenario | Before | After | Reduction | Disabled |
| --- | ---: | ---: | ---: | ---: |
| chain, 1,000 additions | 254,251 B | 84,531 B | 66.75% | 3,745 B |
| chain, 10,000 additions | 3,402,091 B | 1,313,331 B | 61.40% | 3,745 B |
| chain, 100,000 additions | 29,277,163 B | 10,488,371 B | 64.18% | 3,745 B |
| growing dependencies, 32 rounds | 159,282 B | 99,330 B | 37.64% | 52,330 B |
| growing dependencies, 128 rounds | 1,363,480 B | 620,968 B | 54.46% | 210,106 B |
| growing dependencies, 512 rounds | 17,278,072 B | 6,248,200 B | 63.84% | 850,593 B |

`chain` repeatedly adds a neutral zero to one challenge/message product without
registering the intermediate results. Its provenance set stays unchanged, so
new operations reuse one submitted-set allocation. `rounds` registers a fresh
message each round, multiplies the previous response by the next challenge,
adds the message and registers the response. This exercises expanding sets.
Both modes produce the same transcript lengths in these fixtures.

The legacy current-round challenge-product fixture remains available, but does
not model accumulating submitted dependencies. Existing three-argument calls
continue to select it; the optional fourth argument chooses a new fixture:

```bash
cargo build --release --example memory_usage
target/release/examples/memory_usage full 100000 1 chain
target/release/examples/memory_usage full 128 1 rounds
bash scripts/measure_memory.sh
```

The script respects `CARGO_TARGET_DIR` and emits:

```text
mode,scenario,count,challenges_per_round,retained_bytes,peak_bytes,transcript_bytes
```

### Time comparison

The existing `full_protocol/full` benchmark was run against both implementations
with unchanged fixtures. Medians of Criterion's 30 samples are reported below;
the run had scheduling outliers, so these are indicative local measurements,
not a production performance guarantee or a Plonky3 benchmark.

| Rounds | Before | After | Reduction |
| ---: | ---: | ---: | ---: |
| 1 | 2.626 µs | 2.429 µs | 7.50% |
| 8 | 33.004 µs | 28.244 µs | 14.42% |
| 32 | 258.767 µs | 230.291 µs | 11.00% |
| 128 | 3.026 ms | 2.749 ms | 9.14% |

Run the current version with:

```bash
cargo bench --bench transcript_benchmarks -- full_protocol/full --noplot
```

These times include registration, cumulative transcript hashing, native integer
arithmetic and destruction of the inspector, not just provenance merging. The
integer response is not reduced after every multiplication and can grow.

### Remaining costs

For N records and up to R rounds in a submitted set, the worst-case retained
journal storage is still O(N × R). Sharing reduces repeated allocations, not the
cost of every distinct widening set. With fixed provenance the journal itself
still grows as O(N). An exact equality/subset/merge may take O(R) work, while
latest-challenge comparison and fetching the largest submitted round are O(1).
No full journal traversal is required per operation.

The mutex, reference counts, labels, full operation history and cumulative
`challenges` input sets remain. Both inspection modes also keep the elements and
transcript bytes; challenge batches clone the transcript temporarily to preserve
atomicity. Those independent costs were not removed by this optimization.

## Historical baseline

All numerical tables below predate automatic computation-origin recording. They
are retained as historical evidence, not measurements of the current code or a
direct before/after comparison with the optimization above. In particular, the
old constant-time check figures do not measure the current provenance work or
shared-lock overhead. The older full-protocol fixture also differed from the
current expanding-dependency scenario.

## Method

Time measurements use Criterion 0.8.2 and the optimized Cargo profile. Every
benchmark uses 30 samples, a 500 ms warm-up and a 2 s measurement window. The
tables report the median because unrelated activity on a development machine can
produce high-latency outliers.

The benchmarks cover:

- registration of transcript elements
- generation of one challenge as the transcript grows
- generation of several challenges in one logical round
- complete multi-round transcript processing
- cross-round dependency checks
- `Full` and `Disabled` inspection modes

Run the time benchmarks with:

```bash
cargo bench --bench transcript_benchmarks -- --noplot
```

The memory probe uses a counting global allocator in a separate release process.
It reports the peak additional live heap allocation while constructing the
scenario. Run the measurement matrix with:

```bash
bash scripts/measure_memory.sh
```

The recorded environment used Rust 1.95.0 on Linux. Absolute values depend on
the processor, allocator and system load, so comparisons should be repeated on
the target integration environment.

## Time results

### Element registration

| Elements | `Full` | `Disabled` |
| ---: | ---: | ---: |
| 16 | 5.279 µs | 4.687 µs |
| 64 | 21.521 µs | 17.966 µs |
| 256 | 83.941 µs | 70.534 µs |
| 1024 | 331.279 µs | 281.035 µs |

Registration grows approximately linearly in both modes. `Full` additionally
creates dependency metadata for each registered element.

### Challenge generation by number of registered elements

| Elements | `Full` | `Disabled` |
| ---: | ---: | ---: |
| 16 | 3.416 µs | 2.172 µs |
| 64 | 10.436 µs | 6.219 µs |
| 256 | 46.243 µs | 28.554 µs |
| 1024 | 184.017 µs | 106.504 µs |

Both modes hash the same cryptographic transcript. `Full` also verifies the
challenge input and stores its element dependencies.

### Challenge batch

| Challenges in one round | `Full` | `Disabled` |
| ---: | ---: | ---: |
| 1 | 2.514 µs | 1.620 µs |
| 2 | 3.557 µs | 2.556 µs |
| 4 | 6.113 µs | 4.851 µs |
| 8 | 12.012 µs | 9.709 µs |

Batch cost grows approximately linearly because every extracted challenge is
added to the cryptographic transcript before the next extraction.

### Complete multi-round scenario

| Rounds | `Full` | `Disabled` | `Full` overhead |
| ---: | ---: | ---: | ---: |
| 1 | 2.137 µs | 1.554 µs | 37.5% |
| 8 | 18.019 µs | 12.117 µs | 48.7% |
| 32 | 137.370 µs | 82.568 µs | 66.4% |
| 128 | 1.525 ms | 0.922 ms | 65.5% |

The complete scenario grows faster than linearly because every later challenge
intentionally includes all preceding prover responses. This increases both the
hashed transcript and the retained challenge dependency sets.

### Cross-round check

| Protocol rounds | `Full` | `Disabled` |
| ---: | ---: | ---: |
| 2 | 71.7 ns | 1.1 ns |
| 8 | 72.5 ns | 1.1 ns |
| 32 | 71.0 ns | 1.1 ns |
| 128 | 72.4 ns | 1.1 ns |

For an object with one registered challenge dependency, the optimized `Full`
check no longer depends on the total number of protocol rounds. `Disabled`
returns immediately.

## Memory results

| Rounds | Challenges per round | `Full` | `Disabled` |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 3,822 B | 3,078 B |
| 8 | 1 | 15,271 B | 12,065 B |
| 32 | 1 | 64,406 B | 47,254 B |
| 128 | 1 | 341,840 B | 188,111 B |
| 32 | 8 | 295,574 B | 185,754 B |

The `Full` result includes dependency metadata required for later inspection.
The `Disabled` result retains element labels for structural validation but does
not construct the unused challenge graphs.

## Optimizations in the measured baseline

- cross-round checks inspected only the dependencies of the two participating
  objects and allocate no temporary sets
- `Disabled` mode did not construct `challenges` and `challenges_mul`
- challenge input sets store existing element indices instead of cloned labels
- challenge input information remains available and its contents are covered by
  a regression test

At 128 rounds, the cross-round check decreased from a recorded median of about
3.187 µs to 72.4 ns. Peak memory for the `Full` scenario decreased from 599,089
to 341,840 bytes, while `Disabled` decreased from 599,089 to 188,111 bytes.

Further compression of retained challenge inputs is possible, but it would trade
away the direct set representation or introduce shared allocation structures.
The current representation keeps the original challenge-to-input mapping and
removes repeated string storage without adding another user-visible wrapper.
