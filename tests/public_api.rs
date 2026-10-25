use fs_vuln_detection::{
    FSHash, InspectionMode, TaggedValue, TranscriptError, TranscriptInspector, Value
};
use num_bigint::BigInt;
use sha3::Sha3_256;

#[test]
fn public_api_supports_a_complete_protocol_round() {
    let mut transcript = TranscriptInspector::new(b"public-api-test");
    let order = BigInt::from(97);

    let generator = transcript.add_generator("g", BigInt::from(2)).unwrap();
    let secret = transcript.add_constant("secret", BigInt::from(3)).unwrap();
    let public_key = (generator * secret).unwrap();
    let public_key = transcript
        .add_public_key("public_key", public_key.into_value())
        .unwrap();
    let message = transcript.add_message("message", BigInt::from(5)).unwrap();

    let challenge = transcript
        .record_challenge::<Sha3_256>(
            "challenge",
            &["g", "public_key", "message"],
            &order
        )
        .unwrap();
    let expected = BigInt::from(6) - challenge.as_bigint().unwrap() * BigInt::from(5);
    let challenge_message = (challenge * message).unwrap();
    let response = (public_key - challenge_message).unwrap();

    let response = transcript
        .add_response("response", response)
        .unwrap();

    assert_eq!(response.as_bigint(), Some(&expected));
}

#[test]
fn response_from_another_transcript_is_rejected() {
    let mut first = TranscriptInspector::new(b"first-protocol");
    let mut second = TranscriptInspector::new(b"second-protocol");
    let foreign_response = second.add_constant("value", Value::int(5)).unwrap();

    let result = first.add_response("response", foreign_response);

    assert!(matches!(result, Err(TranscriptError::DifferentTranscripts)));
}

#[test]
fn public_api_tracks_a_multi_round_dependency_chain() {
    let order = BigInt::from(97);
    let mut transcript = TranscriptInspector::new(b"multi-round-api-test");
    let generator = transcript.add_generator("g", BigInt::from(2)).unwrap();
    transcript.add_message("m", BigInt::from(3)).unwrap();

    let mut first_round = transcript
        .record_challenges::<Sha3_256>(&["y", "z"], &["g", "m"], &order)
        .unwrap();
    let z = first_round.pop().unwrap();
    let y = first_round.pop().unwrap();
    let first_response = (y * z).unwrap();
    let first_response = transcript
        .add_response("r1", first_response)
        .unwrap();

    let challenge = transcript
        .record_challenge::<Sha3_256>("x", &["g", "m", "r1"], &order)
        .unwrap();
    let second_response = (challenge * &first_response).unwrap();
    let second_response = transcript
        .add_response("r2", second_response)
        .unwrap();

    assert!((&second_response + first_response).is_ok());
    assert!((second_response + generator).is_ok());
}

#[test]
fn failed_validation_does_not_change_a_later_challenge() {
    let order = BigInt::from(97);
    let mut recovered = TranscriptInspector::new(b"atomic-recovery-test");
    let mut clean = TranscriptInspector::new(b"atomic-recovery-test");

    for transcript in [&mut recovered, &mut clean] {
        transcript.add_generator("g", BigInt::from(2)).unwrap();
        transcript.add_message("m", BigInt::from(3)).unwrap();
    }

    assert!(recovered
        .record_challenge::<Sha3_256>("invalid", &["g"], &order)
        .is_err());

    let recovered_challenge = recovered
        .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
        .unwrap();
    let clean_challenge = clean
        .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
        .unwrap();

    assert_eq!(recovered_challenge.as_bigint(), clean_challenge.as_bigint());
    assert_eq!(recovered.transcript_bytes(), clean.transcript_bytes());
}

#[test]
fn public_api_preserves_challenges_when_inspection_is_disabled() {
    fn run(mode: InspectionMode) -> (Vec<BigInt>, Vec<u8>) {
        let order = BigInt::from(97);
        let mut transcript = TranscriptInspector::with_mode(b"mode-test", mode);
        transcript.add_generator("g", BigInt::from(2)).unwrap();
        let mut response = transcript.add_message("m", BigInt::from(3)).unwrap();
        let mut public_names = vec!["g".to_string(), "m".to_string()];
        let mut challenges = Vec::new();

        for round in 0..8 {
            let challenge_name = format!("e_{round}");
            let response_name = format!("r_{round}");
            let used_names: Vec<&str> = public_names.iter().map(String::as_str).collect();
            let challenge = transcript
                .record_challenge::<Sha3_256>(
                    &challenge_name,
                    &used_names,
                    &order
                )
                .unwrap();
            challenges.push(challenge.as_bigint().unwrap().clone());
            response = (challenge * response).unwrap();
            response = transcript.add_response(&response_name, response).unwrap();
            public_names.push(response_name);
        }

        (challenges, transcript.transcript_bytes().to_vec())
    }

    let full = run(InspectionMode::Full);
    let disabled = run(InspectionMode::Disabled);

    assert_eq!(full, disabled);
}

// fixed nonzero challenges isolate dependency checks from hash output edge cases
struct TestHash;

impl FSHash for TestHash {
    fn hash(_input: &[u8]) -> Vec<u8> {
        vec![7]
    }
}

fn test_round(label: &[u8]) -> (TranscriptInspector, TaggedValue, TaggedValue) {
    let mut transcript = TranscriptInspector::new(label);
    transcript.add_generator("g", BigInt::from(2)).unwrap();
    let message = transcript.add_message("m", BigInt::from(3)).unwrap();
    let challenge = transcript
        .record_challenge::<TestHash>("e", &["g", "m"], &BigInt::from(97))
        .unwrap();
    (transcript, message, challenge)
}

fn assert_suspicious(result: Result<TaggedValue, TranscriptError>) {
    assert!(matches!(
        result,
        Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _))
    ));
}

#[test]
fn challenge_dependencies_do_not_require_multiplication() {
    let (mut transcript, message, challenge) = test_round(b"challenge-arithmetic");
    let later = transcript.add_message("later", BigInt::from(11)).unwrap();
    let before = transcript.transcript_bytes().to_vec();

    assert_eq!((&challenge + &message).unwrap().as_bigint(), Some(&BigInt::from(10)));
    assert_eq!((&challenge - &message).unwrap().as_bigint(), Some(&BigInt::from(4)));
    assert_eq!((&message + &challenge).unwrap().as_bigint(), Some(&BigInt::from(10)));
    assert_eq!((&message - &challenge).unwrap().as_bigint(), Some(&BigInt::from(-4)));
    let combined = (&challenge + &message).unwrap();
    assert_suspicious(combined + later);
    assert_eq!(transcript.transcript_bytes(), before);
}

#[test]
fn unused_multiplication_does_not_change_response_dependencies() {
    let (mut transcript, message, challenge) = test_round(b"unused-multiplication");
    let before = transcript.transcript_bytes().to_vec();
    let _unused = (challenge * &message).unwrap();

    assert_eq!(transcript.transcript_bytes(), before);
    let response = transcript.add_response("response", message).unwrap();
    let later = transcript.add_message("later", BigInt::from(11)).unwrap();

    assert_suspicious(response + later);
}

#[test]
fn later_challenges_can_cover_earlier_messages() {
    let (mut transcript, message, first_challenge) = test_round(b"later-challenge");
    let first_response = (first_challenge * &message).unwrap();
    let first_response = transcript.add_response("r1", first_response).unwrap();
    let later = transcript.add_message("later", BigInt::from(11)).unwrap();
    assert_suspicious(&first_response + &later);
    let next_challenge = transcript
        .record_challenge::<TestHash>("next", &["g", "m", "r1", "later"], &BigInt::from(97))
        .unwrap();
    let second_response = (next_challenge * &message).unwrap();
    let second_response = transcript.add_response("r2", second_response).unwrap();

    assert!((&second_response + first_response).is_ok());
    assert!((&second_response + message).is_ok());
    assert!((second_response + later).is_ok());
}

#[test]
fn equal_values_do_not_share_challenge_identity() {
    let (mut transcript, message, challenge) = test_round(b"equal-challenge-values");
    let same_value = transcript
        .add_message("same_value", challenge.as_bigint().unwrap().clone())
        .unwrap();
    assert_eq!(same_value.value(), challenge.value());
    assert_suspicious(same_value * &message);
    let related = (challenge * message).unwrap();

    let related = transcript.add_response("related", related).unwrap();
    assert_eq!(related.as_bigint(), Some(&BigInt::from(21)));
}

#[test]
fn challenge_alias_keeps_its_original_round() {
    let (mut transcript, message, challenge) = test_round(b"challenge-alias-round");
    let alias = transcript.add_response("alias", challenge).unwrap();
    transcript
        .record_challenge::<TestHash>(
            "next",
            &["g", "m", "alias"],
            &BigInt::from(97)
        )
        .unwrap();
    let later = transcript.add_message("later", BigInt::from(11)).unwrap();
    let alias = transcript.add_response("second_alias", alias).unwrap();
    let response = (alias * &message).unwrap();
    let response = transcript.add_response("response", response).unwrap();

    assert!((&response + message).is_ok());
    assert_suspicious(response + later);
}

#[test]
fn modulo_preserves_dependencies_from_both_operands() {
    let (mut transcript, message, challenge) = test_round(b"modulo-dependencies");
    let product = (challenge * &message).unwrap();
    let plain = transcript.add_constant("plain", BigInt::from(13)).unwrap();
    let order = transcript.add_constant("order", BigInt::from(97)).unwrap();
    let modulus_related = plain.modulo(&product).unwrap();
    let related = product.modulo(&order).unwrap();
    let modulus_related = transcript.add_response("modulus_related", modulus_related).unwrap();
    let related = transcript.add_response("related", related).unwrap();
    let later = transcript.add_message("later", BigInt::from(11)).unwrap();

    assert!((&modulus_related + &message).is_ok());
    assert!((&related + message).is_ok());
    assert_suspicious(modulus_related + &later);
    assert_suspicious(related + later);
}

#[test]
fn modpow_preserves_known_base_dependencies() {
    let (mut transcript, message, challenge) = test_round(b"modpow-dependencies");
    let product = (&challenge * &message).unwrap();
    let powered = product.modpow(&BigInt::from(1), &BigInt::from(97)).unwrap();

    assert_eq!(product.value(), powered.value());
    let powered = transcript.add_response("powered", powered).unwrap();
    assert!((&powered + &message).is_ok());
    let later = transcript.add_message("later", BigInt::from(11)).unwrap();
    assert_suspicious(&powered + &later);

    let next_challenge = transcript
        .record_challenge::<TestHash>("next", &["g", "m", "powered", "later"], &BigInt::from(97))
        .unwrap();
    let next_response = (next_challenge * &powered).unwrap();
    let next_response = transcript.add_response("next_response", next_response).unwrap();

    assert!((&next_response + &powered).is_ok());
    assert!((&next_response + &message).is_ok());
    assert!((next_response + later).is_ok());

    let restored = (challenge * powered).unwrap();
    let restored = transcript.add_response("restored", restored).unwrap();
    assert!((restored + message).is_ok());
}

#[test]
fn registered_response_alias_preserves_dependencies() {
    let (mut transcript, message, challenge) = test_round(b"response-alias-dependencies");
    let response = (challenge * &message).unwrap();
    let response = transcript.add_response("response", response).unwrap();
    let alias = transcript.add_response("alias", response.clone()).unwrap();
    transcript
        .record_challenge::<TestHash>(
            "next",
            &["g", "m", "response", "alias"],
            &BigInt::from(97)
        )
        .unwrap();
    let later_alias = transcript.add_response("later_alias", alias).unwrap();
    let later = transcript.add_message("later", BigInt::from(11)).unwrap();

    assert!((&later_alias + &message).is_ok());
    assert!((&later_alias + &response).is_ok());
    assert!((response + message).is_ok());
    assert_suspicious(later_alias + later);
}

#[test]
fn long_expression_chains_preserve_dependencies() {
    let (mut transcript, message, _first_challenge) = test_round(b"long-expression-chain");
    let later = transcript.add_message("later", BigInt::from(11)).unwrap();
    let challenge = transcript
        .record_challenge::<TestHash>("next", &["g", "m", "later"], &BigInt::from(97))
        .unwrap();
    let zero = transcript.add_constant("zero", BigInt::from(0)).unwrap();
    let mut response = (challenge * &message).unwrap();

    for _ in 0..20_000 {
        response = (response + &zero).unwrap();
    }
    let response = transcript.add_response("response", response).unwrap();
    let newest = transcript.add_message("newest", BigInt::from(13)).unwrap();

    assert!((&response + message).is_ok());
    assert!((&response + later).is_ok());
    assert_suspicious(response + newest);
}

#[test]
fn derived_challenge_expression_preserves_dependencies() {
    let (mut transcript, message, challenge) = test_round(b"derived-challenge-operand");
    let zero = transcript.add_constant("zero", BigInt::from(0)).unwrap();
    let derived_challenge = (&challenge + &zero).unwrap();
    assert_eq!((derived_challenge * &message).unwrap().as_bigint(), Some(&BigInt::from(21)));
    let derived_message = (message + zero).unwrap();
    let related = (challenge * derived_message).unwrap();

    let related = transcript.add_response("related", related).unwrap();
    assert_eq!(related.as_bigint(), Some(&BigInt::from(21)));
}

#[test]
fn each_challenge_in_a_round_preserves_dependencies() {
    let mut transcript = TranscriptInspector::new(b"same-round-challenges");
    transcript.add_generator("g", BigInt::from(2)).unwrap();
    let message = transcript.add_message("m", BigInt::from(3)).unwrap();
    let challenges = transcript
        .record_challenges::<TestHash>(&["y", "z", "w"], &["g", "m"], &BigInt::from(97))
        .unwrap();

    for (index, challenge) in challenges.into_iter().enumerate() {
        let response = (challenge * &message).unwrap();
        let label = format!("response_{index}");
        let response = transcript.add_response(&label, response).unwrap();
        assert!((response + &message).is_ok());
    }
}

#[test]
fn received_responses_do_not_inherit_local_computation_history() {
    let (mut transcript, message, challenge) = test_round(b"received-response");
    let local = (challenge * &message).unwrap();
    let received = transcript.add_received_response("received", local.value().clone()).unwrap();
    let generator = transcript.add_generator("another_g", BigInt::from(2)).unwrap();

    assert_eq!(local.value(), received.value());
    assert!((&local + &message).is_ok());
    assert_suspicious(&received + &message);
    assert_eq!((&received * generator).unwrap().as_bigint(), Some(&BigInt::from(42)));

    let next_challenge = transcript
        .record_challenge::<TestHash>(
            "next", &["g", "m", "received", "another_g"], &BigInt::from(97)
        )
        .unwrap();
    let bound_received = (next_challenge + received).unwrap();
    assert_eq!((bound_received + message).unwrap().as_bigint(), Some(&BigInt::from(31)));
}

#[test]
fn received_responses_preserve_hashing_when_inspection_is_disabled() {
    fn run(mode: InspectionMode) -> (BigInt, Vec<u8>) {
        let mut transcript = TranscriptInspector::with_mode(b"received-response-mode", mode);
        transcript.add_generator("g", BigInt::from(2)).unwrap();
        transcript.add_message("m", BigInt::from(3)).unwrap();
        transcript.record_challenge::<Sha3_256>("first", &["g", "m"], &BigInt::from(97)).unwrap();
        transcript.add_received_response("response", BigInt::from(29)).unwrap();
        let challenge = transcript
            .record_challenge::<Sha3_256>("next", &["g", "m", "response"], &BigInt::from(97))
            .unwrap();
        (challenge.as_bigint().unwrap().clone(), transcript.transcript_bytes().to_vec())
    }

    assert_eq!(run(InspectionMode::Full), run(InspectionMode::Disabled));
}

#[test]
fn local_and_received_response_provenance() {
    let (mut transcript, _message, challenge) = test_round(b"response-origin-boundary");
    let secret = transcript.add_constant("secret", BigInt::from(3)).unwrap();
    let computed = (challenge * secret).unwrap();
    let local = transcript.add_response("local", computed).unwrap();
    let received = transcript.add_received_response("received", local.value().clone()).unwrap();
    transcript.record_challenge::<TestHash>(
        "next", &["g", "m", "local", "received"], &BigInt::from(97)
    ).unwrap();
    let later = transcript.add_message("later", BigInt::from(11)).unwrap();

    // local registration preserves known provenance without adding a submitted-input round
    // the same bytes received externally are a fresh input, not a reconstructed computation
    assert_eq!(local.value(), received.value());
    assert_eq!((local + &later).unwrap().as_bigint(), Some(&BigInt::from(32)));
    assert_suspicious(&received + &later);

    let covering = transcript.record_challenge::<TestHash>(
        "covering", &["g", "m", "local", "received", "later"], &BigInt::from(97)
    ).unwrap();
    let related = (covering + received).unwrap();
    assert_eq!((related + later).unwrap().as_bigint(), Some(&BigInt::from(39)));
}
