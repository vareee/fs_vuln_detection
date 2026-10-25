use fs_vuln_detection::{
    FSHash, InspectionMode, TaggedValue, TranscriptError, TranscriptInspector, Value
};
use num_bigint::BigInt;
use sha3::Sha3_256;

// fixed challenges isolate dependency checks from hash output edge cases
struct TestHash;

impl FSHash for TestHash {
    fn hash(_input: &[u8]) -> Vec<u8> {
        vec![7]
    }
}

fn first_round(mode: InspectionMode) -> (TranscriptInspector, TaggedValue, TaggedValue) {
    let mut transcript = TranscriptInspector::with_mode(b"automatic-arithmetic", mode);
    transcript.add_generator("g", BigInt::from(2)).unwrap();
    let message = transcript.add_message("m0", BigInt::from(3)).unwrap();
    let challenge = transcript
        .record_challenge::<TestHash>("e0", &["g", "m0"], &BigInt::from(97))
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
fn addition_checks_all_ownership_forms_immediately() {
    let (mut transcript, earlier, _challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();

    assert_suspicious(&earlier + &later);
    assert_suspicious(earlier.clone() + &later);
    assert_suspicious(&earlier + later.clone());
    assert_suspicious(earlier.clone() + later.clone());
    assert_suspicious(&later + &earlier);
    assert_suspicious(later.clone() + &earlier);
    assert_suspicious(&later + earlier.clone());
    assert_suspicious(later + earlier);
}

#[test]
fn subtraction_checks_all_ownership_forms_immediately() {
    let (mut transcript, earlier, _challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();

    assert_suspicious(&earlier - &later);
    assert_suspicious(earlier.clone() - &later);
    assert_suspicious(&earlier - later.clone());
    assert_suspicious(earlier.clone() - later.clone());
    assert_suspicious(&later - &earlier);
    assert_suspicious(later.clone() - &earlier);
    assert_suspicious(&later - earlier.clone());
    assert_suspicious(later - earlier);
}

#[test]
fn multiplication_checks_all_ownership_forms_immediately() {
    let (mut transcript, earlier, _challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();

    assert_suspicious(&earlier * &later);
    assert_suspicious(earlier.clone() * &later);
    assert_suspicious(&earlier * later.clone());
    assert_suspicious(earlier.clone() * later.clone());
    assert_suspicious(&later * &earlier);
    assert_suspicious(later.clone() * &earlier);
    assert_suspicious(&later * earlier.clone());
    assert_suspicious(later * earlier);
}

#[test]
fn challenges_can_participate_in_any_arithmetic_operation() {
    let (_transcript, message, challenge) = first_round(InspectionMode::Full);

    assert_eq!((&challenge + &message).unwrap().as_bigint(), Some(&BigInt::from(10)));
    assert_eq!((&message + &challenge).unwrap().as_bigint(), Some(&BigInt::from(10)));
    assert_eq!((&challenge - &message).unwrap().as_bigint(), Some(&BigInt::from(4)));
    assert_eq!((&message - &challenge).unwrap().as_bigint(), Some(&BigInt::from(-4)));
    assert_eq!((&challenge * &message).unwrap().as_bigint(), Some(&BigInt::from(21)));
    assert_eq!((&message * &challenge).unwrap().as_bigint(), Some(&BigInt::from(21)));
    assert_eq!(challenge.modulo(&message).unwrap().as_bigint(), Some(&BigInt::from(1)));
    assert_eq!(message.modulo(&challenge).unwrap().as_bigint(), Some(&BigInt::from(3)));
}

#[test]
fn messages_from_one_round_do_not_require_a_challenge() {
    let (mut transcript, _earlier, _challenge) = first_round(InspectionMode::Full);
    let first = transcript.add_message("first", BigInt::from(11)).unwrap();
    let second = transcript.add_message("second", BigInt::from(5)).unwrap();

    assert_eq!((&first + &second).unwrap().as_bigint(), Some(&BigInt::from(16)));
    assert_eq!((&first - &second).unwrap().as_bigint(), Some(&BigInt::from(6)));
    assert_eq!((&first * &second).unwrap().as_bigint(), Some(&BigInt::from(55)));
    assert_eq!(first.modulo(&second).unwrap().as_bigint(), Some(&BigInt::from(1)));
}

#[test]
fn an_earlier_challenge_does_not_cover_a_later_message() {
    let (mut transcript, earlier, challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();
    let earlier_product = (&challenge * &earlier).unwrap();
    let later_product = (&challenge * &later).unwrap();

    assert_suspicious(&earlier_product + &later);
    assert_suspicious(&later + &earlier_product);
    assert_suspicious(&later_product + &earlier);
    assert_suspicious(&earlier + &later_product);
    assert_suspicious(earlier_product + later_product);
}

#[test]
fn later_challenges_cover_earlier_messages() {
    let (mut transcript, earlier, first_challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();
    let next_challenge = transcript
        .record_challenge::<TestHash>("e1", &["g", "m0", "m1"], &BigInt::from(97))
        .unwrap();
    let later_product = (&next_challenge * &earlier).unwrap();
    let earlier_product = (first_challenge * &earlier).unwrap();
    let covered_later = (&next_challenge + &later).unwrap();

    assert_eq!((&later_product + &later).unwrap().as_bigint(), Some(&BigInt::from(32)));
    assert_eq!((&later + &later_product).unwrap().as_bigint(), Some(&BigInt::from(32)));
    assert_eq!((earlier_product + covered_later).unwrap().as_bigint(), Some(&BigInt::from(39)));
    let zero = transcript.add_constant("zero", BigInt::from(0)).unwrap();
    let derived_challenge = (next_challenge + zero).unwrap();
    let derived_product = (derived_challenge * earlier).unwrap();
    assert_eq!((derived_product + later).unwrap().as_bigint(), Some(&BigInt::from(32)));
}

#[test]
fn registering_aliases_does_not_reassign_their_provenance() {
    let (mut transcript, earlier, challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();
    let alias = transcript.add_response("message_alias", earlier).unwrap();
    let challenge_alias = transcript.add_response("challenge_alias", challenge).unwrap();
    let related = (challenge_alias * &alias).unwrap();
    let related = transcript.add_response("related_alias", related).unwrap();

    assert_suspicious(&alias + &later);
    assert_suspicious(&later * &alias);
    assert_suspicious(related + later);
}

#[test]
fn constants_and_generators_are_neutral_but_are_not_challenges() {
    let (mut transcript, earlier, _challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();
    let constant = transcript.add_constant("constant", BigInt::from(7)).unwrap();
    let generator = transcript.add_generator("another_g", BigInt::from(7)).unwrap();
    let earlier_constant = (&constant * &earlier).unwrap();
    let earlier_generator = (&generator * &earlier).unwrap();

    assert_eq!((&constant + &later).unwrap().as_bigint(), Some(&BigInt::from(18)));
    assert_eq!((&generator * &later).unwrap().as_bigint(), Some(&BigInt::from(77)));
    assert_suspicious(earlier_constant + &later);
    assert_suspicious(earlier_generator + later);
}

#[test]
fn test_multi_round_arithmetic() {
    let (mut transcript, first_message, first_challenge) = first_round(InspectionMode::Full);
    let mut response = (first_challenge + &first_message).unwrap();
    let mut names = vec!["g".to_string(), "m0".to_string()];

    for round in 1..32 {
        let label = format!("m{round}");
        let message = transcript.add_message(&label, BigInt::from(round + 3)).unwrap();
        names.push(label);
        assert_suspicious(&response + &message);
        assert_suspicious(&message + &response);

        let used: Vec<&str> = names.iter().map(String::as_str).collect();
        let challenge = transcript
            .record_challenge::<TestHash>(&format!("e{round}"), &used, &BigInt::from(97))
            .unwrap();
        let covered_response = (&challenge + response).unwrap();
        response = (covered_response + message).unwrap();
        assert!((&response + &first_message).is_ok());
    }
}

#[test]
fn challenges_in_one_batch_share_their_transcript_boundary() {
    let mut transcript = TranscriptInspector::new(b"automatic-challenge-batch");
    transcript.add_generator("g", BigInt::from(2)).unwrap();
    let earlier = transcript.add_message("m0", BigInt::from(3)).unwrap();
    let challenges = transcript
        .record_challenges::<TestHash>(&["x", "y", "z"], &["g", "m0"], &BigInt::from(97))
        .unwrap();
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();

    for challenge in &challenges {
        let related = (challenge + &earlier).unwrap();
        assert_eq!(related.as_bigint(), Some(&BigInt::from(10)));
        assert_suspicious(related + &later);
    }
    let sum = (&challenges[0] + &challenges[1]).unwrap();
    let related = (sum * earlier).unwrap();
    assert_eq!(related.as_bigint(), Some(&BigInt::from(42)));
    assert_suspicious(related + later);
}

#[test]
fn rejected_subexpressions_are_reported_before_outer_operations() {
    let (mut transcript, earlier, _challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();
    let next_challenge = transcript
        .record_challenge::<TestHash>("e1", &["g", "m0", "m1"], &BigInt::from(97))
        .unwrap();
    let mut outer_operation_ran = false;
    let result = (&earlier + &later).and_then(|sum| {
        outer_operation_ran = true;
        &next_challenge * sum
    });

    assert_suspicious(result);
    assert!(!outer_operation_ran);
    let product = (next_challenge * earlier).unwrap();
    assert_eq!((product + later).unwrap().as_bigint(), Some(&BigInt::from(32)));
}

#[test]
fn unused_operations_do_not_authorize_other_values() {
    let (mut transcript, earlier, _challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();
    let next_challenge = transcript
        .record_challenge::<TestHash>("e1", &["g", "m0", "m1"], &BigInt::from(97))
        .unwrap();
    let _unused = (next_challenge * &earlier).unwrap();

    assert_suspicious(&earlier + &later);
    assert_suspicious(later * earlier);
}

#[test]
fn modulo_checks_and_preserves_both_operands() {
    let (mut transcript, earlier, _challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();
    assert_suspicious(earlier.modulo(&later));
    assert_suspicious(later.modulo(&earlier));
    let next_challenge = transcript
        .record_challenge::<TestHash>("e1", &["g", "m0", "m1"], &BigInt::from(97))
        .unwrap();
    let order = transcript.add_constant("order", BigInt::from(97)).unwrap();
    let numerator_related = (&next_challenge * &earlier).unwrap().modulo(&order).unwrap();
    let modulus_related = earlier.modulo(&next_challenge).unwrap();

    assert_eq!((numerator_related + &later).unwrap().as_bigint(), Some(&BigInt::from(32)));
    assert_eq!((modulus_related + &later).unwrap().as_bigint(), Some(&BigInt::from(14)));
    let submitted_modulus = order.modulo(&earlier).unwrap();
    assert_suspicious(submitted_modulus + later);
}

#[test]
fn raw_modpow_preserves_known_base_provenance() {
    let (mut transcript, earlier, _challenge) = first_round(InspectionMode::Full);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();
    let next_challenge = transcript
        .record_challenge::<TestHash>("e1", &["g", "m0", "m1"], &BigInt::from(97))
        .unwrap();
    let product = (&next_challenge * &earlier).unwrap();
    let powered = product.modpow(&BigInt::from(1), &BigInt::from(97)).unwrap();

    assert_eq!(product.value(), powered.value());
    assert_eq!((powered + &later).unwrap().as_bigint(), Some(&BigInt::from(32)));
    let transformed_challenge = next_challenge.modpow(&BigInt::from(1), &BigInt::from(97)).unwrap();
    let transformed_product = (transformed_challenge * &earlier).unwrap();
    assert_eq!((transformed_product + &later).unwrap().as_bigint(), Some(&BigInt::from(32)));
    let unbound = earlier.modpow(&BigInt::from(1), &BigInt::from(97)).unwrap();
    assert_suspicious(unbound + later);
}

#[test]
fn list_elements_preserve_their_source_provenance() {
    let mut transcript = TranscriptInspector::new(b"automatic-list-elements");
    transcript.add_generator("g", BigInt::from(2)).unwrap();
    let list = transcript.add_message("list", vec![Value::int(3)]).unwrap();
    let challenge = transcript
        .record_challenge::<TestHash>("e0", &["g", "list"], &BigInt::from(97))
        .unwrap();
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();
    let item = list.get(0).unwrap();

    assert_suspicious(&item + &later);
    let related = (challenge * item).unwrap();
    assert_eq!(related.as_bigint(), Some(&BigInt::from(21)));
    assert_suspicious(related + later);
}

#[test]
fn disabled_mode_preserves_numbers_without_arithmetic_checks() {
    let (mut transcript, earlier, challenge) = first_round(InspectionMode::Disabled);
    let later = transcript.add_message("m1", BigInt::from(11)).unwrap();
    let before = transcript.transcript_bytes().to_vec();

    assert_eq!((&challenge + &earlier).unwrap().as_bigint(), Some(&BigInt::from(10)));
    assert_eq!((&earlier + &later).unwrap().as_bigint(), Some(&BigInt::from(14)));
    assert_eq!((&earlier - &later).unwrap().as_bigint(), Some(&BigInt::from(-8)));
    assert_eq!((&earlier * &later).unwrap().as_bigint(), Some(&BigInt::from(33)));
    assert_eq!(earlier.modulo(&later).unwrap().as_bigint(), Some(&BigInt::from(3)));
    assert_eq!(transcript.transcript_bytes(), before);
}

#[test]
fn rejected_arithmetic_does_not_change_bytes_or_later_challenges() {
    let (mut recovered, earlier, _challenge) = first_round(InspectionMode::Full);
    let (mut clean, _clean_message, _clean_challenge) = first_round(InspectionMode::Full);
    let later = recovered.add_message("m1", BigInt::from(11)).unwrap();
    clean.add_message("m1", BigInt::from(11)).unwrap();
    let before = recovered.transcript_bytes().to_vec();

    assert_suspicious(&earlier + &later);
    assert_suspicious(&earlier - &later);
    assert_suspicious(&earlier * &later);
    assert_suspicious(earlier.modulo(&later));
    assert_eq!(recovered.transcript_bytes(), before);
    assert_eq!(recovered.transcript_bytes(), clean.transcript_bytes());

    let recovered_challenge = recovered
        .record_challenge::<Sha3_256>("next", &["g", "m0", "m1"], &BigInt::from(97))
        .unwrap();
    let clean_challenge = clean
        .record_challenge::<Sha3_256>("next", &["g", "m0", "m1"], &BigInt::from(97))
        .unwrap();

    assert_eq!(recovered_challenge.value(), clean_challenge.value());
    assert_eq!(recovered.transcript_bytes(), clean.transcript_bytes());
}

#[test]
fn arithmetic_checks_survive_inspector_moves_and_scoped_threads() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<TaggedValue>();
    assert_send_sync::<TranscriptInspector>();
    let (mut original, earlier, challenge) = first_round(InspectionMode::Full);
    let later = original.add_message("m1", BigInt::from(11)).unwrap();
    let moved = original;
    let before = moved.transcript_bytes().to_vec();

    let product = std::thread::scope(|scope| {
        let suspicious = scope.spawn(|| &earlier + &later);
        let allowed = scope.spawn(|| (&challenge * &earlier).unwrap());
        assert_suspicious(suspicious.join().unwrap());
        allowed.join().unwrap()
    });

    assert_eq!((&product + earlier).unwrap().as_bigint(), Some(&BigInt::from(24)));
    assert_suspicious(product + later);
    assert_eq!(moved.transcript_bytes(), before);
}
