use fs_vuln_detection::{
    InspectionMode, TranscriptError, TranscriptInspector, Value, secp256k1_order
};
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use sha3::Sha3_256;

const SCHNORR_LABEL: &[u8] = b"binding-tests/schnorr/v1/secp256k1";
const SCHNORR_INPUTS: &[&str] = &["g", "public_key", "commitment", "message"];

fn point_bytes(point: &ProjectivePoint) -> [u8; 33] {
    point.to_affine().to_encoded_point(true).as_bytes().try_into().unwrap()
}

fn scalar_bytes(value: &BigInt) -> [u8; 32] {
    assert!(value >= &BigInt::from(0));
    assert!(value < &secp256k1_order());
    let (_, bytes) = value.to_bytes_be();
    let mut encoded = [0; 32];
    encoded[32 - bytes.len()..].copy_from_slice(&bytes);
    encoded
}

fn decode_point(bytes: &[u8; 33]) -> Option<ProjectivePoint> {
    let encoded = EncodedPoint::from_bytes(bytes).ok()?;
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;
    if point.to_encoded_point(true).as_bytes() != bytes {
        return None;
    }
    Some(point.into())
}

fn decode_proof(proof: &[u8; 65]) -> Option<(ProjectivePoint, BigInt)> {
    let commitment = decode_point(&proof[..33].try_into().ok()?)?;
    let response_bytes: [u8; 32] = proof[33..].try_into().ok()?;
    Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(response_bytes)))?;
    let response = BigInt::from_bytes_be(Sign::Plus, &response_bytes);
    Some((commitment, response))
}

// this deterministic Schnorr fixture tests an actual verification equation, not BIP 340 encoding
// only public data and canonical proof bytes cross the prover/verifier boundary
fn prove_schnorr(mode: InspectionMode) -> ([u8; 65], [u8; 33], BigInt, Vec<u8>) {
    let mut prover = TranscriptInspector::with_mode(SCHNORR_LABEL, mode);
    let order = secp256k1_order();
    let generator = prover.add_generator("g", ProjectivePoint::GENERATOR).unwrap();
    let secret = prover.add_constant("secret", Value::int(7)).unwrap();
    let nonce = prover.add_constant("nonce", Value::int(11)).unwrap();
    let modulus = prover.add_constant("order", order.clone()).unwrap();
    let public_key = (&generator * &secret).unwrap();
    let public_key = prover.add_public_key("public_key", public_key.into_value()).unwrap();
    let commitment = (&generator * &nonce).unwrap();
    let commitment = prover.add_commitment("commitment", commitment.into_value()).unwrap();
    prover.add_message("message", Value::int(42)).unwrap();
    let challenge = prover.record_challenge::<Sha3_256>(
        "e", SCHNORR_INPUTS, &order
    ).unwrap();
    let challenge_value = challenge.as_bigint().unwrap().clone();
    let challenge_secret = (&challenge * secret).unwrap();
    let response = (nonce + challenge_secret).unwrap().modulo(&modulus).unwrap();
    let response = prover.add_response("response", response).unwrap();

    let mut proof = [0; 65];
    proof[..33].copy_from_slice(&point_bytes(commitment.as_point().unwrap()));
    proof[33..].copy_from_slice(&scalar_bytes(response.as_bigint().unwrap()));
    (
        proof,
        point_bytes(public_key.as_point().unwrap()),
        challenge_value,
        prover.transcript_bytes().to_vec()
    )
}

fn verify_schnorr(
    mode: InspectionMode,
    proof: &[u8; 65],
    public_key: &[u8; 33],
    message: i32
) -> (bool, bool, BigInt, Vec<u8>) {
    let (commitment, response) = decode_proof(proof).unwrap();
    let public_key = decode_point(public_key).unwrap();
    let mut verifier = TranscriptInspector::with_mode(SCHNORR_LABEL, mode);
    let generator = verifier.add_generator("g", ProjectivePoint::GENERATOR).unwrap();
    let public_key = verifier.add_public_key("public_key", public_key).unwrap();
    let commitment = verifier.add_commitment("commitment", commitment).unwrap();
    verifier.add_message("message", Value::int(message)).unwrap();
    let challenge = verifier.record_challenge::<Sha3_256>(
        "e", SCHNORR_INPUTS, &secp256k1_order()
    ).unwrap();
    let challenge_value = challenge.as_bigint().unwrap().clone();
    let response = verifier.add_received_response("response", response).unwrap();
    let lhs = (response * generator).unwrap();
    let challenge_key = (challenge * public_key).unwrap();
    let rhs = (commitment + challenge_key).unwrap();
    let valid = lhs.value() == rhs.value();

    // equality is a native protocol check, not a claim that the heuristic proves validity
    // subtracting the two sides exposes a documented heuristic false positive
    let residual_is_suspicious = match &lhs - &rhs {
        Ok(_) => false,
        Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _)) => true,
        Err(error) => panic!("unexpected residual error: {error}")
    };
    (
        valid,
        residual_is_suspicious,
        challenge_value,
        verifier.transcript_bytes().to_vec()
    )
}

#[test]
fn schnorr_proof_verifies_with_independent_inspectors() {
    let (proof, public_key, challenge, transcript) = prove_schnorr(InspectionMode::Full);
    let (valid, _, verifier_challenge, verifier_transcript) = verify_schnorr(
        InspectionMode::Full, &proof, &public_key, 42
    );

    assert!(valid);
    assert_eq!(challenge, verifier_challenge);
    assert_eq!(transcript, verifier_transcript);
}

#[test]
fn schnorr_proof_and_transcript_do_not_depend_on_inspection_mode() {
    let full = prove_schnorr(InspectionMode::Full);
    let disabled = prove_schnorr(InspectionMode::Disabled);
    assert_eq!(full, disabled);

    let full_verification = verify_schnorr(InspectionMode::Full, &full.0, &full.1, 42);
    let disabled_verification = verify_schnorr(InspectionMode::Disabled, &full.0, &full.1, 42);
    assert!(full_verification.0);
    assert!(disabled_verification.0);
    assert_eq!(full_verification.2, disabled_verification.2);
    assert_eq!(full_verification.3, disabled_verification.3);
    assert!(!disabled_verification.1);
}

#[test]
fn schnorr_verifier_rejects_tampered_proof_and_public_inputs() {
    let (proof, public_key, _, _) = prove_schnorr(InspectionMode::Full);
    let mut changed_response = proof;
    let response = decode_proof(&proof).unwrap().1;
    let changed_scalar = (response + BigInt::from(1)).mod_floor(&secp256k1_order());
    changed_response[33..].copy_from_slice(&scalar_bytes(&changed_scalar));

    let mut changed_commitment = proof;
    changed_commitment[..33].copy_from_slice(&point_bytes(
        &(ProjectivePoint::GENERATOR * Scalar::from(13u64))
    ));
    let changed_key = point_bytes(&(ProjectivePoint::GENERATOR * Scalar::from(8u64)));

    // each case reaches the native equation and fails it, rather than relying on a warning
    for mode in [InspectionMode::Full, InspectionMode::Disabled] {
        for (candidate, key, message) in [
            (&changed_response, &public_key, 42),
            (&changed_commitment, &public_key, 42),
            (&proof, &public_key, 43),
            (&proof, &changed_key, 42)
        ] {
            assert!(!verify_schnorr(mode, candidate, key, message).0);
        }
    }
}

#[test]
fn schnorr_proof_decoder_rejects_noncanonical_scalar_and_invalid_point() {
    let (proof, _, _, _) = prove_schnorr(InspectionMode::Full);
    let mut invalid_scalar = proof;
    invalid_scalar[33..].fill(0xff);
    assert!(decode_proof(&invalid_scalar).is_none());

    let mut invalid_point = proof;
    invalid_point[..33].fill(0);
    assert!(decode_proof(&invalid_point).is_none());
}

#[test]
fn valid_schnorr_equation_can_still_trigger_a_residual_warning() {
    let (proof, public_key, _, _) = prove_schnorr(InspectionMode::Full);
    let (valid, residual_is_suspicious, _, _) = verify_schnorr(
        InspectionMode::Full, &proof, &public_key, 42
    );

    assert!(valid);
    assert!(residual_is_suspicious);
}

// this fixture reproduces Bulletproofs transcript ordering and one coefficient pattern
// it is not a complete range proof and does not establish Bulletproofs integration
fn bulletproof_transcript(mode: InspectionMode) -> (Vec<BigInt>, Vec<u8>, ProjectivePoint) {
    let mut transcript = TranscriptInspector::with_mode(
        b"binding-tests/bulletproof-shape/v1/secp256k1", mode
    );
    transcript.add_generator("g", ProjectivePoint::GENERATOR).unwrap();
    transcript.add_message("message", Value::int(42)).unwrap();
    let a = transcript.add_commitment(
        "A", ProjectivePoint::GENERATOR * Scalar::from(2u64)
    ).unwrap();
    let s_point = ProjectivePoint::GENERATOR * Scalar::from(3u64);
    let s = transcript.add_commitment("S", s_point).unwrap();
    let first_challenges = transcript.record_challenges::<Sha3_256>(
        &["y", "z"], &["g", "message", "A", "S"], &secp256k1_order()
    ).unwrap();
    let t1 = transcript.add_commitment(
        "T1", ProjectivePoint::GENERATOR * Scalar::from(5u64)
    ).unwrap();
    transcript.add_commitment(
        "T2", ProjectivePoint::GENERATOR * Scalar::from(7u64)
    ).unwrap();
    let x = transcript.record_challenge::<Sha3_256>(
        "x", &["g", "message", "A", "S", "T1", "T2"], &secp256k1_order()
    ).unwrap();

    let mut challenges: Vec<BigInt> = first_challenges.iter()
        .map(|challenge| challenge.as_bigint().unwrap().clone()).collect();
    challenges.push(x.as_bigint().unwrap().clone());
    let x_scalar = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(
        scalar_bytes(x.as_bigint().unwrap())
    ))).unwrap();
    let x_s = (&x * s).unwrap();
    assert_eq!(x_s.as_point(), Some(&(s_point * x_scalar)));
    let early_expression = (a + x_s).unwrap();
    let late_expression = (x * t1).unwrap();
    let combined = (early_expression + late_expression).unwrap();

    (challenges, transcript.transcript_bytes().to_vec(), *combined.as_point().unwrap())
}

#[test]
fn bulletproof_late_challenge_can_multiply_an_early_commitment() {
    let full = bulletproof_transcript(InspectionMode::Full);
    let disabled = bulletproof_transcript(InspectionMode::Disabled);

    assert_eq!(full, disabled);
}

#[test]
fn bulletproof_shaped_mixing_warns_without_a_late_challenge() {
    let mut transcript = TranscriptInspector::new(b"bulletproof-stale-challenge-test");
    transcript.add_generator("g", Value::int(2)).unwrap();
    transcript.add_message("message", Value::int(3)).unwrap();
    let a = transcript.add_commitment("A", Value::int(5)).unwrap();
    let s = transcript.add_commitment("S", Value::int(7)).unwrap();
    let challenges = transcript.record_challenges::<Sha3_256>(
        &["y", "z"], &["g", "message", "A", "S"], &secp256k1_order()
    ).unwrap();
    let t1 = transcript.add_commitment("T1", Value::int(11)).unwrap();
    transcript.add_commitment("T2", Value::int(13)).unwrap();
    let before = transcript.transcript_bytes().to_vec();

    let early_expression = (a + (&challenges[0] * s).unwrap()).unwrap();
    let late_expression = (&challenges[0] * t1).unwrap();
    assert!(matches!(
        early_expression + late_expression,
        Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _))
    ));
    assert_eq!(transcript.transcript_bytes(), before);
}

#[test]
fn bulletproof_challenge_requires_late_commitments_in_declaration() {
    let mut transcript = TranscriptInspector::new(b"bulletproof-declaration-test");
    transcript.add_generator("g", Value::int(2)).unwrap();
    transcript.add_message("message", Value::int(3)).unwrap();
    transcript.add_commitment("A", Value::int(5)).unwrap();
    transcript.add_commitment("S", Value::int(7)).unwrap();
    transcript.record_challenges::<Sha3_256>(
        &["y", "z"], &["g", "message", "A", "S"], &secp256k1_order()
    ).unwrap();
    transcript.add_commitment("T1", Value::int(11)).unwrap();
    transcript.add_commitment("T2", Value::int(13)).unwrap();
    let before = transcript.transcript_bytes().to_vec();

    // used_names is an audited declaration, not a selector of already serialized bytes
    let incomplete = transcript.record_challenge::<Sha3_256>(
        "x", &["g", "message", "A", "S", "T1"], &secp256k1_order()
    );
    assert!(matches!(incomplete, Err(TranscriptError::NotEveryProverMessagesIncluded)));
    assert_eq!(transcript.transcript_bytes(), before);
    assert!(transcript.record_challenge::<Sha3_256>(
        "x", &["g", "message", "A", "S", "T1", "T2"], &secp256k1_order()
    ).is_ok());
}
