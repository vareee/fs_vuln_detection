## About

This project is aimed to create mechanism which can be used to find vulnerabilities in Fiat-Shamir transfromation implementations.

Main mechanism is being realised on Rust. 

MVP on Python is stored on python_proto dir.

## Challenge generation

`TranscriptInspector::record_challenge` creates a scalar Fiat-Shamir challenge as
`H(transcript || challenge_label) mod order`. The order is supplied for each
generation operation because one transcript may contain challenges for different
groups. It is not stored as a property of the transcript.

`TranscriptInspector::record_challenges` creates several scalar challenges in one
logical round. All challenges in that batch use the same order. Challenges with
different orders are created by separate calls.

This API deliberately describes scalar challenges only. An extension-field
challenge or a bit challenge must be sampled according to the native protocol
rules instead of being represented as an integer modulo an artificial order. The
Plonky3 proof of concept will define that adapter at the integration boundary.
