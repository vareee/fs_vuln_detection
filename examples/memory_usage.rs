use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};

use fs_vuln_detection::{InspectionMode, TranscriptInspector};
use num_bigint::BigInt;
use sha3::Sha3_256;

struct MeasuringAllocator;

static ENABLED: AtomicBool = AtomicBool::new(false);
static CURRENT: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn record_allocation(size: usize) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let current = CURRENT.fetch_add(size as isize, Ordering::Relaxed) + size as isize;
    if current > 0 {
        PEAK.fetch_max(current as usize, Ordering::Relaxed);
    }
}

fn record_deallocation(size: usize) {
    if ENABLED.load(Ordering::Relaxed) {
        CURRENT.fetch_sub(size as isize, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for MeasuringAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record_deallocation(layout.size());
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(
        &self,
        pointer: *mut u8,
        old_layout: Layout,
        new_size: usize
    ) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, old_layout, new_size) };
        if !new_pointer.is_null() && ENABLED.load(Ordering::Relaxed) {
            let difference = new_size as isize - old_layout.size() as isize;
            let current = CURRENT.fetch_add(difference, Ordering::Relaxed) + difference;
            if current > 0 {
                PEAK.fetch_max(current as usize, Ordering::Relaxed);
            }
        }
        new_pointer
    }
}

#[global_allocator]
static ALLOCATOR: MeasuringAllocator = MeasuringAllocator;

fn parse_mode(value: &str) -> InspectionMode {
    match value {
        "full" => InspectionMode::Full,
        "disabled" => InspectionMode::Disabled,
        _ => panic!("mode must be 'full' or 'disabled'")
    }
}

fn run_protocol(
    mode: InspectionMode,
    rounds: usize,
    challenges_per_round: usize
) -> TranscriptInspector {
    let order = BigInt::from(97);
    let mut transcript = TranscriptInspector::with_mode(b"memory/protocol/v1", mode);
    transcript.add_generator("g", BigInt::from(2)).unwrap();
    transcript.add_message("m", BigInt::from(3)).unwrap();
    let factor = transcript.add_constant("factor", BigInt::from(3)).unwrap();
    let mut used_names = vec!["g".to_string(), "m".to_string()];

    for round in 0..rounds {
        let challenge_names: Vec<String> = (0..challenges_per_round)
            .map(|index| format!("e_{round}_{index}"))
            .collect();
        let challenge_refs: Vec<&str> =
            challenge_names.iter().map(String::as_str).collect();
        let used: Vec<&str> = used_names.iter().map(String::as_str).collect();
        let mut challenges = transcript
            .record_challenges::<Sha3_256>(&challenge_refs, &used, &order)
            .unwrap()
            .into_iter();
        let mut response = (challenges.next().unwrap() * &factor).unwrap();
        for challenge in challenges {
            let term = (challenge * &factor).unwrap();
            response = (response + term).unwrap();
        }
        let response_name = format!("r_{round}");
        transcript
            .add_response(&response_name, response)
            .unwrap();
        used_names.push(response_name);
    }

    transcript
}

fn run_chain(mode: InspectionMode, operations: usize) -> TranscriptInspector {
    let mut transcript = TranscriptInspector::with_mode(b"memory/chain/v1", mode);
    transcript.add_generator("g", BigInt::from(2)).unwrap();
    let message = transcript.add_message("m", BigInt::from(3)).unwrap();
    let zero = transcript.add_constant("zero", BigInt::from(0)).unwrap();
    let challenge = transcript
        .record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97))
        .unwrap();
    let mut result = (challenge * message).unwrap();
    for _ in 0..operations {
        result = std::hint::black_box((result + &zero).unwrap());
    }
    std::hint::black_box(result);
    transcript
}

fn run_rounds(mode: InspectionMode, rounds: usize) -> TranscriptInspector {
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
        response = ((challenge * response).unwrap() + message).unwrap();
        response = transcript.add_response(&response_name, response).unwrap();
        used_names.push(response_name);
    }
    transcript
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    assert!(
        (4..=5).contains(&arguments.len()),
        "usage: memory_usage <full|disabled> <count> <challenges-per-round> [legacy|chain|rounds]"
    );
    let mode = parse_mode(&arguments[1]);
    let count = arguments[2].parse::<usize>().expect("count must be an integer");
    let challenges = arguments[3]
        .parse::<usize>()
        .expect("challenges-per-round must be an integer");
    let scenario = arguments.get(4).map(String::as_str).unwrap_or("legacy");
    assert!(count > 0, "count must be greater than zero");
    assert!(challenges > 0, "challenges-per-round must be greater than zero");
    assert!(
        matches!(scenario, "legacy" | "chain" | "rounds"),
        "scenario must be 'legacy', 'chain' or 'rounds'"
    );
    assert!(
        scenario == "legacy" || challenges == 1,
        "chain and rounds scenarios use exactly one challenge per round"
    );

    CURRENT.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    ENABLED.store(true, Ordering::Relaxed);
    let transcript = match scenario {
        "chain" => run_chain(mode, count),
        "rounds" => run_rounds(mode, count),
        _ => run_protocol(mode, count, challenges)
    };
    ENABLED.store(false, Ordering::Relaxed);

    println!(
        "{},{},{},{},{},{},{}",
        arguments[1],
        scenario,
        count,
        challenges,
        CURRENT.load(Ordering::Relaxed),
        PEAK.load(Ordering::Relaxed),
        transcript.transcript_bytes().len()
    );
}
