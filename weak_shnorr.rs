// examples of Shnorr implementing weak Fiat-Shamir

use rand::Rng;
use sha3::Sha3_256;
use num_bigint::{BigInt, RandBigInt};
use num_traits::One;
use k256::ProjectivePoint;
use crate::poc::{
    secp256k1_order, ObjectCategory, TaggedValue,
    TranscriptInspector, Value,
};



// get random scalar
fn rand_scalar(rng: &mut impl Rng) -> BigInt {
    let n = secp256k1_order();
    rng.gen_bigint_range(&BigInt::one(), &n)
}

// add generator element to a provided transcript
fn add_generator(t: &mut TranscriptInspector, name: &str, subject: &str) -> TaggedValue {
    t.add(name, subject, ObjectCategory::Generator,
          Value::Point(ProjectivePoint::GENERATOR))
        .expect("generator add")
}

// example of safe transcript
pub fn safe_transcript_example() -> Result<String, String> {
    let mut t = TranscriptInspector::with_label(b"safe_transcript");
    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let g = add_generator(&mut t, "gen", "prover1");

    let a1 = t.add("a1", "prover1", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let A1 = (&g * a1).map_err(|e| format!("Detected: {}", e))?;
    t.add("A1", "prover1", ObjectCategory::Pubkey, A1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k1 = t.add("k1", "prover1", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let R1 = (&g * k1).map_err(|e| format!("Detected: {}", e))?;
    t.add("R1", "prover1", ObjectCategory::Commitment, R1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a2 = t.add("a2", "prover2", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let A2 = (&g * a2).map_err(|e| format!("Detected: {}", e))?;
    t.add("A2", "prover2", ObjectCategory::Pubkey, A2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k2 = t.add("k2", "prover2", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let R2 = (&g * k2).map_err(|e| format!("Detected: {}", e))?;
    t.add("R2", "prover2", ObjectCategory::Commitment, R2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let msg_rnd = t.add("msg_rnd", "prover2", ObjectCategory::Constant,
                        Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let msg = (&g * msg_rnd).map_err(|e| format!("Detected: {}", e))?;
    t.add("message", "prover2", ObjectCategory::Message, msg.value)
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

    let msg_rnd = t.add("msg_rnd", "prover1", ObjectCategory::Constant,
                        Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let msg = (&g * msg_rnd).map_err(|e| format!("Detected: {}", e))?;
    t.add("msg", "prover1", ObjectCategory::Message, msg.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a1 = t.add("a1", "prover1", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let A1 = (&g * a1).map_err(|e| format!("Detected: {}", e))?;
    t.add("A1", "prover1", ObjectCategory::Pubkey, A1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k1 = t.add("k1", "prover1", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let R1 = (&g * k1).map_err(|e| format!("Detected: {}", e))?;
    t.add("R1", "prover1", ObjectCategory::Commitment, R1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    t.record_challenge::<Sha3_256>("e1", &["A1", "R1", "msg", "gen"], &n)
        .map_err(|e| format!("Detected: {}", e))?;

    let a2 = t.add("a2", "prover2", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let A2 = (&g * a2).map_err(|e| format!("Detected: {}", e))?;
    match t.add("A2", "prover2", ObjectCategory::Pubkey, A2.value) {
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
    let n1 = t1.add("n", "prover", ObjectCategory::Generator, Value::Integer(n.clone()))
        .map_err(|e| format!("Detected: {}", e))?;

    let msg_rnd1 = t1.add("msg_rnd1", "prover", ObjectCategory::Constant,
                          Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let msg1 = (&g1 * msg_rnd1).map_err(|e| format!("Detected: {}", e))?;
    t1.add("msg", "prover", ObjectCategory::Message, msg1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a1 = t1.add("a1", "prover", ObjectCategory::Constant,
                    Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let A1 = (&g1 * &a1).map_err(|e| format!("Detected: {}", e))?;
    t1.add("A1", "prover", ObjectCategory::Pubkey, A1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k1 = t1.add("k1", "prover", ObjectCategory::Constant,
                    Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let R1 = (&g1 * &k1).map_err(|e| format!("Detected: {}", e))?;
    t1.add("R1", "prover", ObjectCategory::Commitment, R1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let e1 = t1.record_challenge::<Sha3_256>("e1", &["R1", "A1", "msg", "gen"], &n)
        .map_err(|e| format!("Detected: {}", e))?;

    let prod = (&e1 * a1).map_err(|e| format!("Detected: {}", e))?;
    let s1_pre = (k1 + prod).map_err(|e| format!("Detected: {}", e))?;
    let s1_red = s1_pre.modulo(&n1).map_err(|e| format!("Detected: {}", e))?;
    let s1 = t1.add("s1", "prover", ObjectCategory::Message, s1_red.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let mut t2 = TranscriptInspector::with_label(b"cross_transcript_error_2");
    let g2 = add_generator(&mut t2, "gen", "prover");
    let n2 = t2.add("n", "prover", ObjectCategory::Generator, Value::Integer(n.clone()))
        .map_err(|e| format!("Detected: {}", e))?;

    let msg_rnd2 = t2.add("msg_rnd2", "prover", ObjectCategory::Constant,
                          Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let msg2 = (&g2 * msg_rnd2).map_err(|e| format!("Detected: {}", e))?;
    t2.add("msg", "prover", ObjectCategory::Message, msg2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a2 = t2.add("a2", "prover", ObjectCategory::Constant,
                    Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let A2 = (&g2 * &a2).map_err(|e| format!("Detected: {}", e))?;
    let A2 = t2.add("A2", "prover", ObjectCategory::Pubkey, A2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k2 = t2.add("k2", "prover", ObjectCategory::Constant,
                    Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let R2 = (&g2 * &k2).map_err(|e| format!("Detected: {}", e))?;
    let R2 = t2.add("R2", "prover", ObjectCategory::Commitment, R2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let e2 = t2.record_challenge::<Sha3_256>("e2", &["R2", "A2", "msg", "gen"], &n)
        .map_err(|e| format!("Detected: {}", e))?;
    let prod2 = (&e2 * a2).map_err(|e| format!("Detected: {}", e))?;
    let s2_pre = (k2 + prod2).map_err(|e| format!("Detected: {}", e))?;
    let s2_red = s2_pre.modulo(&n2).map_err(|e| format!("Detected: {}", e))?;
    t2.add("s2", "prover", ObjectCategory::Message, s2_red.value)
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

    let msg_rnd = t.add("msg_rnd", "prover", ObjectCategory::Constant,
                        Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let msg = (&g * msg_rnd).map_err(|e| format!("Detected: {}", e))?;
    let msg = t.add("msg", "prover", ObjectCategory::Message, msg.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a = t.add("a", "prover", ObjectCategory::Constant,
                  Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let A = (&g * a).map_err(|e| format!("Detected: {}", e))?;
    let A = t.add("A", "prover", ObjectCategory::Pubkey, A.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k = t.add("k", "prover", ObjectCategory::Constant,
                  Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let R = (&g * k).map_err(|e| format!("Detected: {}", e))?;
    t.add("R", "prover", ObjectCategory::Commitment, R.value)
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
    t.add("A1", "prover1", ObjectCategory::Pubkey, A1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k1 = rand_scalar(&mut rng);
    let R1 = mul_point_scalar(&g, &k1)?;
    t.add("R1", "prover1", ObjectCategory::Commitment, R1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a2 = rand_scalar(&mut rng);
    let A2 = mul_point_scalar(&g, &a2)?;
    t.add("A2", "prover2", ObjectCategory::Pubkey, A2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k2 = rand_scalar(&mut rng);
    let R2 = mul_point_scalar(&g, &k2)?;
    t.add("R2", "prover2", ObjectCategory::Commitment, R2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let msg_rnd = rand_scalar(&mut rng);
    let msg = mul_point_scalar(&g, &msg_rnd)?;
    t.add("message", "prover2", ObjectCategory::Message, msg.value)
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
