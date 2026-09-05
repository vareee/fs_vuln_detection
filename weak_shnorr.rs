// examples of Shnorr implementing weak Fiat-Shamir

use rand::Rng;
use sha3::Sha3_256;
use num_bigint::{BigInt, RandBigInt};
use num_traits::One;
use k256::ProjectivePoint;
use crate::poc::{
    secp256k1_order, TaggedValue,
    TranscriptInspector, Value,
};



// get random scalar
fn rand_scalar(rng: &mut impl Rng) -> BigInt {
    let n = secp256k1_order();
    rng.gen_bigint_range(&BigInt::one(), &n)
}

// add generator element to a provided transcript
fn add_generator(t: &mut TranscriptInspector, name: &str, subject: &str) -> TaggedValue {
    t.add_generator_for(name, subject, Value::Point(ProjectivePoint::GENERATOR))
        .expect("generator add")
}

// example of safe transcript
pub fn safe_transcript_example() -> Result<String, String> {
    let mut t = TranscriptInspector::with_label(b"safe_transcript");
    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let g = add_generator(&mut t, "gen", "prover1");

    let a1 = t.add_constant_for("a1", "prover1", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let A1 = (&g * a1).map_err(|e| format!("Detected: {}", e))?;
    t.add_public_key_for("A1", "prover1", A1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k1 = t.add_constant_for("k1", "prover1", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let R1 = (&g * k1).map_err(|e| format!("Detected: {}", e))?;
    t.add_commitment_for("R1", "prover1", R1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a2 = t.add_constant_for("a2", "prover2", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let A2 = (&g * a2).map_err(|e| format!("Detected: {}", e))?;
    t.add_public_key_for("A2", "prover2", A2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k2 = t.add_constant_for("k2", "prover2", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let R2 = (&g * k2).map_err(|e| format!("Detected: {}", e))?;
    t.add_commitment_for("R2", "prover2", R2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let msg_rnd = t.add_constant_for("msg_rnd", "prover2", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let msg = (&g * msg_rnd).map_err(|e| format!("Detected: {}", e))?;
    t.add_message_for("message", "prover2", msg.value)
        .map_err(|e| format!("Detected: {}", e))?;

    t.record_challenge::<Sha3_256>("e", &["A1", "A2", "R1", "R2", "message", "gen"], &n)
        .map_err(|e| format!("Detected: {}", e))?;

    Ok("No Fiat-Shamir heuristic vulnerability detected.".to_string())
}

// example of transcript with TranscriptError
pub fn transcript_error_example() -> Result<String, String> {
    let mut t = TranscriptInspector::with_label(b"transcript_with_order_error");
    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let g = add_generator(&mut t, "gen", "prover1");

    let msg_rnd = t.add_constant_for("msg_rnd", "prover1", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let msg = (&g * msg_rnd).map_err(|e| format!("Detected: {}", e))?;
    t.add_message_for("msg", "prover1", msg.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a1 = t.add_constant_for("a1", "prover1", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let A1 = (&g * a1).map_err(|e| format!("Detected: {}", e))?;
    t.add_public_key_for("A1", "prover1", A1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k1 = t.add_constant_for("k1", "prover1", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let R1 = (&g * k1).map_err(|e| format!("Detected: {}", e))?;
    t.add_commitment_for("R1", "prover1", R1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    t.record_challenge::<Sha3_256>("e1", &["A1", "R1", "msg", "gen"], &n)
        .map_err(|e| format!("Detected: {}", e))?;

    let a2 = t.add_constant_for("a2", "prover2", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let A2 = (&g * a2).map_err(|e| format!("Detected: {}", e))?;
    match t.add_public_key_for("A2", "prover2", A2.value) {
        Ok(_)  => Ok("No Fiat-Shamir heuristic vulnerability detected.".to_string()),
        Err(e) => Err(format!("Detected: {}", e)),
    }
}

// example of cross transcript interaction with error
pub fn cross_transcript_interaction_example() -> Result<String, String> {
    fn bad_verify(
        R: &TaggedValue, A: &TaggedValue, s: &TaggedValue, e: &TaggedValue, G: &TaggedValue
    ) -> Result<bool, String> {
        let lhs = (s * G).map_err(|err| err.to_string())?;
        let ea  = (e * A).map_err(|err| err.to_string())?;
        let rhs = (R + ea).map_err(|err| err.to_string())?;
        Ok(lhs.value == rhs.value)
    }

    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let mut t1 = TranscriptInspector::with_label(b"cross_transcript_1");
    let g1 = add_generator(&mut t1, "gen", "prover");
    let n1 = t1.add_generator_for("n", "prover", Value::Integer(n.clone()))
        .map_err(|e| format!("Detected: {}", e))?;

    let msg_rnd1 = t1.add_constant("msg_rnd1", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let msg1 = (&g1 * msg_rnd1).map_err(|e| format!("Detected: {}", e))?;
    t1.add_message("msg", msg1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a1 = t1.add_constant("a1", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let A1 = (&g1 * &a1).map_err(|e| format!("Detected: {}", e))?;
    t1.add_public_key("A1", A1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k1 = t1.add_constant("k1", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let R1 = (&g1 * &k1).map_err(|e| format!("Detected: {}", e))?;
    t1.add_commitment("R1", R1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let e1 = t1.record_challenge::<Sha3_256>("e1", &["R1", "A1", "msg", "gen"], &n)
        .map_err(|e| format!("Detected: {}", e))?;

    let prod = (&e1 * a1).map_err(|e| format!("Detected: {}", e))?;
    let s1_pre = (k1 + prod).map_err(|e| format!("Detected: {}", e))?;
    let s1_red = s1_pre.modulo(&n1).map_err(|e| format!("Detected: {}", e))?;
    let s1 = t1.add_message("s1", s1_red.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let mut t2 = TranscriptInspector::with_label(b"cross_transcript_error_2");
    let g2 = add_generator(&mut t2, "gen", "prover");
    let n2 = t2.add_generator_for("n", "prover", Value::Integer(n.clone()))
        .map_err(|e| format!("Detected: {}", e))?;

    let msg_rnd2 = t2.add_constant("msg_rnd2", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let msg2 = (&g2 * msg_rnd2).map_err(|e| format!("Detected: {}", e))?;
    t2.add_message("msg", msg2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a2 = t2.add_constant("a2", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let A2 = (&g2 * &a2).map_err(|e| format!("Detected: {}", e))?;
    let A2 = t2.add_public_key("A2", A2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k2 = t2.add_constant("k2", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let R2 = (&g2 * &k2).map_err(|e| format!("Detected: {}", e))?;
    let R2 = t2.add_commitment("R2", R2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let e2 = t2.record_challenge::<Sha3_256>("e2", &["R2", "A2", "msg", "gen"], &n)
        .map_err(|e| format!("Detected: {}", e))?;
    let prod2 = (&e2 * a2).map_err(|e| format!("Detected: {}", e))?;
    let s2_pre = (k2 + prod2).map_err(|e| format!("Detected: {}", e))?;
    let s2_red = s2_pre.modulo(&n2).map_err(|e| format!("Detected: {}", e))?;
    t2.add_message("s2", s2_red.value)
        .map_err(|e| format!("Detected: {}", e))?;

    match bad_verify(&R2, &A2, &s1, &e1, &g2) {
        Ok(_)    => Ok("No Fiat-Shamir heuristic vulnerability detected.".to_string()),
        Err(err) => Err(format!("Detected: {}", err)),
    }
}

// example of cross round object ineraction with error
pub fn cross_round_interaction_example() -> Result<String, String> {
    let mut t = TranscriptInspector::with_label(b"cross_round_transcript");
    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let g = add_generator(&mut t, "gen", "prover2");

    let msg_rnd = t.add_constant("msg_rnd", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let msg = (&g * msg_rnd).map_err(|e| format!("Detected: {}", e))?;
    let msg = t.add_message("msg", msg.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a = t.add_constant("a", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let A = (&g * a).map_err(|e| format!("Detected: {}", e))?;
    let A = t.add_public_key("A", A.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k = t.add_constant("k", Value::Integer(rand_scalar(&mut rng)))
        .map_err(|e| format!("Detected: {}", e))?;
    let R = (&g * k).map_err(|e| format!("Detected: {}", e))?;
    t.add_commitment("R", R.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let e1 = t.record_challenge::<Sha3_256>("e1", &["A", "R", "msg", "gen"], &n)
        .map_err(|e| format!("Detected: {}", e))?;

    let e1_msg = (e1 * &msg).map_err(|e| format!("Detected: {}", e))?;
    let z1 = (&A - &e1_msg).map_err(|e| format!("Detected: {}", e))?;
    t.add_response("Z1", z1.value, &["e1"])
        .map_err(|e| format!("Detected: {}", e))?;

    let e2 = t.record_challenge::<Sha3_256>("e2", &["A", "R", "msg", "gen", "Z1"], &n)
        .map_err(|e| format!("Detected: {}", e))?;

    let e2_msg = (e2 * msg).map_err(|e| format!("Detected: {}", e))?;
    let z2 = (A - e2_msg).map_err(|e| format!("Detected: {}", e))?;
    t.add_response("Z2", z2.value, &["e2"])
        .map_err(|e| format!("Detected: {}", e))?;

    match t.check_cross_round_interaction("Z2", "A") {
        Ok(_)    => Ok("No Fiat-Shamir heuristic vulnerability detected.".to_string()),
        Err(err) => Err(format!("Detected: {}", err)),
    }
}

// example of interaction with not constants
pub fn non_constant_interaction_example() -> Result<String, String> {
    let mut t = TranscriptInspector::with_label(b"non_const_transcript");
    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let g = add_generator(&mut t, "gen", "prover1");

    let a1 = rand_scalar(&mut rng);
    let A1 = mul_point_scalar(&g, &a1)?;
    t.add_public_key_for("A1", "prover1", A1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k1 = rand_scalar(&mut rng);
    let R1 = mul_point_scalar(&g, &k1)?;
    t.add_commitment_for("R1", "prover1", R1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a2 = rand_scalar(&mut rng);
    let A2 = mul_point_scalar(&g, &a2)?;
    t.add_public_key_for("A2", "prover2", A2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k2 = rand_scalar(&mut rng);
    let R2 = mul_point_scalar(&g, &k2)?;
    t.add_commitment_for("R2", "prover2", R2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let msg_rnd = rand_scalar(&mut rng);
    let msg = mul_point_scalar(&g, &msg_rnd)?;
    t.add_message_for("message", "prover2", msg.value)
        .map_err(|e| format!("Detected: {}", e))?;

    t.record_challenge::<Sha3_256>("e", &["A1", "A2", "R1", "R2", "message", "gen"], &n)
        .map_err(|e| format!("Detected: {}", e))?;

    Ok("No Fiat-Shamir heuristic vulnerability detected.".to_string())
}


fn mul_point_scalar(point: &TaggedValue, scalar: &BigInt) -> Result<TaggedValue, String> {
    use uuid::Uuid;

    let stray_scalar = TaggedValue::new(
        Value::Integer(scalar.clone()),
        Uuid::nil(),
    );

    match point * &stray_scalar {
        Ok(t) => {
            Ok(TaggedValue::new(t.value, point.transcript_id))
        }
        Err(err) => Err(format!("Detected: {}", err)),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn safe_ok() { assert!(safe_transcript_example().is_ok()); }
    #[test] fn transcript_err() { assert!(transcript_error_example().is_err()); }
    #[test] fn cross_transcript_err() { assert!(cross_transcript_interaction_example().is_err()); }
    #[test] fn cross_round_err() { assert!(cross_round_interaction_example().is_err()); }
    #[test] fn non_const_ok() { assert!(non_constant_interaction_example().is_err()); }
}
