use std::hint::black_box;
use std::time::Duration;

use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion,
    Throughput
};
use fs_vuln_detection::{InspectionMode, TranscriptInspector};
use num_bigint::BigInt;
use sha3::Sha3_256;

const ELEMENT_COUNTS: [usize; 4] = [16, 64, 256, 1024];
const ROUND_COUNTS: [usize; 4] = [1, 8, 32, 128];
const CHALLENGE_COUNTS: [usize; 4] = [1, 2, 4, 8];

fn mode_name(mode: InspectionMode) -> &'static str {
    match mode {
        InspectionMode::Full => "full",
        InspectionMode::Disabled => "disabled"
    }
}

fn transcript_with_messages(
    mode: InspectionMode,
    message_count: usize
) -> (TranscriptInspector, Vec<String>) {
    let mut transcript = TranscriptInspector::with_mode(b"benchmark/protocol/v1", mode);
    transcript.add_generator("g", BigInt::from(2)).unwrap();
    let mut used_names = Vec::with_capacity(message_count + 1);
    used_names.push("g".to_string());
    for index in 0..message_count {
        let name = format!("m_{index}");
        transcript
            .add_message(&name, BigInt::from(index + 3))
            .unwrap();
        used_names.push(name);
    }
    (transcript, used_names)
}

fn run_protocol(mode: InspectionMode, rounds: usize) -> TranscriptInspector {
    let order = BigInt::from(97);
    let mut transcript = TranscriptInspector::with_mode(b"benchmark/protocol/v1", mode);
    transcript.add_generator("g", BigInt::from(2)).unwrap();
    let mut response = transcript.add_message("m", BigInt::from(3)).unwrap();
    let mut used_names = vec!["g".to_string(), "m".to_string()];

    for round in 0..rounds {
        let message_name = format!("m_{round}");
        let message = transcript.add_message(&message_name, BigInt::from(3)).unwrap();
        used_names.push(message_name);
        let challenge_name = format!("e_{round}");
        let response_name = format!("r_{round}");
        let used: Vec<&str> = used_names.iter().map(String::as_str).collect();
        let challenge = transcript
            .record_challenge::<Sha3_256>(&challenge_name, &used, &order)
            .unwrap();
        let covered = (challenge * response).unwrap();
        response = (covered + message).unwrap();
        response = transcript.add_response(&response_name, response).unwrap();
        used_names.push(response_name);
    }

    transcript
}

fn benchmark_element_registration(c: &mut Criterion) {
    let mut group = c.benchmark_group("element_registration");
    for mode in [InspectionMode::Full, InspectionMode::Disabled] {
        for count in ELEMENT_COUNTS {
            group.throughput(Throughput::Elements(count as u64));
            group.bench_with_input(
                BenchmarkId::new(mode_name(mode), count),
                &count,
                |b, &count| {
                    b.iter_batched(
                        || TranscriptInspector::with_mode(b"benchmark/protocol/v1", mode),
                        |mut transcript| {
                            for index in 0..count {
                                let name = format!("m_{index}");
                                transcript
                                    .add_message(&name, BigInt::from(index))
                                    .unwrap();
                            }
                            black_box(transcript)
                        },
                        BatchSize::SmallInput
                    )
                }
            );
        }
    }
    group.finish();
}

fn benchmark_challenge_generation(c: &mut Criterion) {
    let order = BigInt::from(97);
    let mut group = c.benchmark_group("challenge_generation_by_elements");
    for mode in [InspectionMode::Full, InspectionMode::Disabled] {
        for count in ELEMENT_COUNTS {
            group.throughput(Throughput::Elements(count as u64));
            group.bench_with_input(
                BenchmarkId::new(mode_name(mode), count),
                &count,
                |b, &count| {
                    b.iter_batched(
                        || transcript_with_messages(mode, count),
                        |(mut transcript, used_names)| {
                            let used: Vec<&str> =
                                used_names.iter().map(String::as_str).collect();
                            black_box(
                                transcript
                                    .record_challenge::<Sha3_256>(
                                        "e",
                                        &used,
                                        &order
                                    )
                                    .unwrap()
                            )
                        },
                        BatchSize::PerIteration
                    )
                }
            );
        }
    }
    group.finish();
}

fn benchmark_challenge_batch(c: &mut Criterion) {
    let order = BigInt::from(97);
    let mut group = c.benchmark_group("challenge_batch");
    for mode in [InspectionMode::Full, InspectionMode::Disabled] {
        for count in CHALLENGE_COUNTS {
            group.throughput(Throughput::Elements(count as u64));
            group.bench_with_input(
                BenchmarkId::new(mode_name(mode), count),
                &count,
                |b, &count| {
                    let challenge_names: Vec<String> =
                        (0..count).map(|index| format!("e_{index}")).collect();
                    b.iter_batched(
                        || transcript_with_messages(mode, 8),
                        |(mut transcript, used_names)| {
                            let challenges: Vec<&str> = challenge_names
                                .iter()
                                .map(String::as_str)
                                .collect();
                            let used: Vec<&str> =
                                used_names.iter().map(String::as_str).collect();
                            black_box(
                                transcript
                                    .record_challenges::<Sha3_256>(
                                        &challenges,
                                        &used,
                                        &order
                                    )
                                    .unwrap()
                            )
                        },
                        BatchSize::SmallInput
                    )
                }
            );
        }
    }
    group.finish();
}

fn benchmark_full_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_protocol");
    for mode in [InspectionMode::Full, InspectionMode::Disabled] {
        for rounds in ROUND_COUNTS {
            group.throughput(Throughput::Elements(rounds as u64));
            group.bench_with_input(
                BenchmarkId::new(mode_name(mode), rounds),
                &rounds,
                |b, &rounds| {
                    b.iter(|| black_box(run_protocol(mode, rounds)))
                }
            );
        }
    }
    group.finish();
}

fn benchmark_cross_round_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("cross_round_check");
    for mode in [InspectionMode::Full, InspectionMode::Disabled] {
        for rounds in [2, 8, 32, 128] {
            let transcript = run_protocol(mode, rounds);
            let newer = format!("r_{}", rounds - 1);
            let older = format!("r_{}", rounds - 2);
            group.bench_with_input(
                BenchmarkId::new(mode_name(mode), rounds),
                &rounds,
                |b, _| {
                    b.iter(|| {
                        black_box(
                            transcript.check_cross_round_interaction(&newer, &older)
                        )
                        .unwrap()
                    })
                }
            );
        }
    }
    group.finish();
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(30)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets =
        benchmark_element_registration,
        benchmark_challenge_generation,
        benchmark_challenge_batch,
        benchmark_full_protocol,
        benchmark_cross_round_check
}
criterion_main!(benches);
