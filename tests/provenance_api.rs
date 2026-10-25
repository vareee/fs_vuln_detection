use fs_vuln_detection::{
    InspectionMode, TaggedValue, TranscriptError, TranscriptInspector
};
use num_bigint::BigInt;
use sha3::Sha3_256;

#[test]
fn full_inspection_requires_a_live_transcript() {
    let (left, right) = {
        let mut transcript = TranscriptInspector::new(b"expired-provenance");
        let left = transcript.add_constant("left", BigInt::from(2)).unwrap();
        let right = transcript.add_constant("right", BigInt::from(3)).unwrap();
        (left, right)
    };

    assert!(matches!(
        &left + &right,
        Err(TranscriptError::InspectionUnavailable)
    ));
    assert!(matches!(
        &left * &right,
        Err(TranscriptError::InspectionUnavailable)
    ));
}

#[test]
fn disabled_values_can_outlive_the_transcript() {
    let (left, right) = {
        let mut transcript = TranscriptInspector::with_mode(
            b"expired-disabled-provenance",
            InspectionMode::Disabled
        );
        let left = transcript.add_constant("left", BigInt::from(2)).unwrap();
        let right = transcript.add_constant("right", BigInt::from(3)).unwrap();
        (left, right)
    };

    let sum = (&left + &right).unwrap();
    let product = (left * right).unwrap();

    assert_eq!(sum.as_bigint(), Some(&BigInt::from(5)));
    assert_eq!(product.as_bigint(), Some(&BigInt::from(6)));
}

#[test]
fn moving_the_transcript_preserves_tagged_values() {
    let mut original = TranscriptInspector::new(b"moved-provenance");
    let left = original.add_constant("left", BigInt::from(2)).unwrap();
    let right = original.add_constant("right", BigInt::from(3)).unwrap();
    let before = original.transcript_bytes().to_vec();
    let mut moved = original;

    let sum = (left + right).unwrap();

    assert_eq!(sum.as_bigint(), Some(&BigInt::from(5)));
    assert_eq!(moved.transcript_bytes(), before);
    let registered = moved.add_response("sum", sum).unwrap();
    assert_eq!(registered.as_bigint(), Some(&BigInt::from(5)));
}

#[test]
fn tagged_values_support_scoped_thread_arithmetic() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<TaggedValue>();
    assert_send_sync::<TranscriptInspector>();

    let mut transcript = TranscriptInspector::new(b"threaded-provenance");
    let left = transcript.add_constant("left", BigInt::from(2)).unwrap();
    let right = transcript.add_constant("right", BigInt::from(3)).unwrap();
    let before = transcript.transcript_bytes().to_vec();

    let sum = std::thread::scope(|scope| {
        let worker = scope.spawn(|| (&left + &right).unwrap());
        worker.join().unwrap()
    });
    let product = (sum * &right).unwrap();

    assert_eq!(product.as_bigint(), Some(&BigInt::from(15)));
    assert_eq!(transcript.transcript_bytes(), before);
    let registered = transcript.add_response("product", product).unwrap();
    assert_eq!(registered.as_bigint(), Some(&BigInt::from(15)));
}

#[test]
fn inspection_modes_preserve_arithmetic_and_challenges() {
    fn run(mode: InspectionMode) -> (Vec<BigInt>, Vec<u8>) {
        let mut transcript = TranscriptInspector::with_mode(
            b"arithmetic-provenance-modes",
            mode
        );
        let order = BigInt::from(97);
        transcript.add_generator("g", BigInt::from(2)).unwrap();
        let key = transcript.add_public_key("key", BigInt::from(13)).unwrap();
        let message = transcript.add_message("m", BigInt::from(3)).unwrap();
        let challenge = transcript
            .record_challenge::<Sha3_256>("e", &["g", "key", "m"], &order)
            .unwrap();
        let before_arithmetic = transcript.transcript_bytes().to_vec();

        let product = (&challenge * &message).unwrap();
        let response = (key - product).unwrap();
        let response_value = response.as_bigint().unwrap().clone();

        assert_eq!(transcript.transcript_bytes(), before_arithmetic);
        transcript.add_response("response", response).unwrap();
        let next_challenge = transcript
            .record_challenge::<Sha3_256>(
                "next",
                &["g", "key", "m", "response"],
                &order
            )
            .unwrap();

        (
            vec![
                challenge.as_bigint().unwrap().clone(),
                response_value,
                next_challenge.as_bigint().unwrap().clone()
            ],
            transcript.transcript_bytes().to_vec()
        )
    }

    assert_eq!(run(InspectionMode::Full), run(InspectionMode::Disabled));
}
