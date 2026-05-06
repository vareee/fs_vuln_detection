use rand::Rng;
use num_bigint::{BigInt, RandBigInt};
use num_traits::One;
use k256::ProjectivePoint;
use crate::poc::{
    secp256k1_order, serialize_tagged, ObjectCategory, TaggedValue,
    TranscriptInspector, Value, H,
};


fn rand_scalar(rng: &mut impl Rng) -> BigInt {
    let n = secp256k1_order();
    rng.gen_bigint_range(&BigInt::one(), &n)
}

fn add_generator(t: &mut TranscriptInspector, name: &str, subject: &str) -> TaggedValue {
    t.add(name, subject, ObjectCategory::Generator,
          Value::Point(ProjectivePoint::GENERATOR))
        .expect("generator add")
}

pub fn safe_transcript_example() -> Result<String, String> {
    let mut t = TranscriptInspector::new();
    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let g = add_generator(&mut t, "gen", "prover1");

    let a1 = t.add("a1", "prover1", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detection: {}", e))?;
    let big_a1 = (&g * &a1).map_err(|e| format!("Detection: {}", e))?;
    let big_a1 = t.add("A1", "prover1", ObjectCategory::Pubkey, big_a1.value)
        .map_err(|e| format!("Detection: {}", e))?;

    let k1 = t.add("k1", "prover1", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detection: {}", e))?;
    let big_r1 = (&g * &k1).map_err(|e| format!("Detection: {}", e))?;
    let big_r1 = t.add("R1", "prover1", ObjectCategory::Commitment, big_r1.value)
        .map_err(|e| format!("Detection: {}", e))?;

    let a2 = t.add("a2", "prover2", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detection: {}", e))?;
    let big_a2 = (&g * &a2).map_err(|e| format!("Detection: {}", e))?;
    let big_a2 = t.add("A2", "prover2", ObjectCategory::Pubkey, big_a2.value)
        .map_err(|e| format!("Detection: {}", e))?;

    let k2 = t.add("k2", "prover2", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detection: {}", e))?;
    let big_r2 = (&g * &k2).map_err(|e| format!("Detection: {}", e))?;
    let big_r2 = t.add("R2", "prover2", ObjectCategory::Commitment, big_r2.value)
        .map_err(|e| format!("Detection: {}", e))?;

    let msg_rnd = t.add("msg_rnd", "prover2", ObjectCategory::Constant,
                        Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detection: {}", e))?;
    let msg = (&g * &msg_rnd).map_err(|e| format!("Detection: {}", e))?;
    let msg = t.add("message", "prover2", ObjectCategory::Message, msg.value)
        .map_err(|e| format!("Detection: {}", e))?;

    let mut data = Vec::new();
    data.extend_from_slice(&serialize_tagged(&big_a1));
    data.extend_from_slice(&serialize_tagged(&big_r1));
    data.extend_from_slice(&serialize_tagged(&big_a2));
    data.extend_from_slice(&serialize_tagged(&big_r2));
    data.extend_from_slice(&serialize_tagged(&msg));
    data.extend_from_slice(&serialize_tagged(&g));

    let e = H(&data, &n);
    t.record_challenge("e", &["A1", "A2", "R1", "R2", "message", "gen"], Value::Integer(e))
        .map_err(|e| format!("Detection: {}", e))?;

    Ok("No Fiat-Shamir heuristic vulnerability detected.".to_string())
}

pub fn transcript_error_example() -> Result<String, String> {
    let mut t = TranscriptInspector::new();
    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let g = add_generator(&mut t, "gen", "prover1");

    let msg_rnd = t.add("msg_rnd", "prover1", ObjectCategory::Constant,
                        Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let msg = (&g * &msg_rnd).map_err(|e| format!("Detected: {}", e))?;
    let msg = t.add("msg", "prover1", ObjectCategory::Message, msg.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a1 = t.add("a1", "prover1", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let big_a1 = (&g * &a1).map_err(|e| format!("Detected: {}", e))?;
    let big_a1 = t.add("A1", "prover1", ObjectCategory::Pubkey, big_a1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k1 = t.add("k1", "prover1", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let big_r1 = (&g * &k1).map_err(|e| format!("Detected: {}", e))?;
    let big_r1 = t.add("R1", "prover1", ObjectCategory::Commitment, big_r1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let mut data = Vec::new();
    data.extend_from_slice(&serialize_tagged(&big_a1));
    data.extend_from_slice(&serialize_tagged(&big_r1));
    data.extend_from_slice(&serialize_tagged(&msg));
    data.extend_from_slice(&serialize_tagged(&g));
    let e1 = H(&data, &n);
    t.record_challenge("e1", &["A1", "R1", "msg", "gen"], Value::Integer(e1))
        .map_err(|e| format!("Detected: {}", e))?;

    let a2 = t.add("a2", "prover2", ObjectCategory::Constant,
                   Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let big_a2 = (&g * &a2).map_err(|e| format!("Detected: {}", e))?;
    match t.add("A2", "prover2", ObjectCategory::Pubkey, big_a2.value) {
        Ok(_)  => Ok("No Fiat-Shamir heuristic vulnerability detected.".to_string()),
        Err(e) => Err(format!("Detected: {}", e)),
    }
}

#[allow(non_snake_case)]
pub fn cross_transcript_interaction_example() -> Result<String, String> {
    fn bad_verify(
        R: &TaggedValue, A: &TaggedValue, s: &TaggedValue, e: &TaggedValue, G: &TaggedValue,
    ) -> Result<bool, String> {
        let lhs = (s * G).map_err(|err| err.to_string())?;
        let ea  = (e * A).map_err(|err| err.to_string())?;
        let rhs = (R + &ea).map_err(|err| err.to_string())?;
        Ok(lhs.value == rhs.value)
    }

    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let mut t1 = TranscriptInspector::new();
    let g1 = add_generator(&mut t1, "gen", "prover");
    let n_t1 = t1.add("n", "prover", ObjectCategory::Generator, Value::Integer(n.clone()))
        .map_err(|e| format!("Detected: {}", e))?;

    let msg_rnd1 = t1.add("msg_rnd1", "prover", ObjectCategory::Constant,
                          Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let msg1 = (&g1 * &msg_rnd1).map_err(|e| format!("Detected: {}", e))?;
    let msg1 = t1.add("msg", "prover", ObjectCategory::Message, msg1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a1 = t1.add("a1", "prover", ObjectCategory::Constant,
                    Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let A1 = (&g1 * &a1).map_err(|e| format!("Detected: {}", e))?;
    let A1 = t1.add("A1", "prover", ObjectCategory::Pubkey, A1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k1 = t1.add("k1", "prover", ObjectCategory::Constant,
                    Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let R1 = (&g1 * &k1).map_err(|e| format!("Detected: {}", e))?;
    let _R1 = t1.add("R1", "prover", ObjectCategory::Commitment, R1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let mut data = Vec::new();
    data.extend_from_slice(&serialize_tagged(&_R1));
    data.extend_from_slice(&serialize_tagged(&A1));
    data.extend_from_slice(&serialize_tagged(&msg1));
    data.extend_from_slice(&serialize_tagged(&g1));
    let e1_val = H(&data, &n);
    let e1 = t1.record_challenge("e1", &["R1", "A1", "msg", "gen"], Value::Integer(e1_val))
        .map_err(|e| format!("Detected: {}", e))?;

    let prod = (&e1 * &a1).map_err(|e| format!("Detected: {}", e))?;
    let s1_pre = (&k1 + &prod).map_err(|e| format!("Detected: {}", e))?;
    let s1_red = s1_pre.modulo(&n_t1).map_err(|e| format!("Detected: {}", e))?;
    let s1 = t1.add("s1", "prover", ObjectCategory::Message, s1_red.value)
        .map_err(|e| format!("Detected: {}", e))?;
    let _ = (A1, _R1);

    let mut t2 = TranscriptInspector::new();
    let g2 = add_generator(&mut t2, "gen", "prover");
    let n_t2 = t2.add("n", "prover", ObjectCategory::Generator, Value::Integer(n.clone()))
        .map_err(|e| format!("Detected: {}", e))?;

    let msg_rnd2 = t2.add("msg_rnd2", "prover", ObjectCategory::Constant,
                          Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let msg2 = (&g2 * &msg_rnd2).map_err(|e| format!("Detected: {}", e))?;
    let _msg2 = t2.add("msg", "prover", ObjectCategory::Message, msg2.value)
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

    let mut data = Vec::new();
    data.extend_from_slice(&serialize_tagged(&R2));
    data.extend_from_slice(&serialize_tagged(&A2));
    data.extend_from_slice(&serialize_tagged(&_msg2));
    data.extend_from_slice(&serialize_tagged(&g2));
    let e2_val = H(&data, &n);
    let _e2 = t2.record_challenge("e2", &["R2", "A2", "msg", "gen"], Value::Integer(e2_val))
        .map_err(|e| format!("Detected: {}", e))?;
    let prod2 = (&_e2 * &a2).map_err(|e| format!("Detected: {}", e))?;
    let s2_pre = (&k2 + &prod2).map_err(|e| format!("Detected: {}", e))?;
    let s2_red = s2_pre.modulo(&n_t2).map_err(|e| format!("Detected: {}", e))?;
    t2.add("s2", "prover", ObjectCategory::Message, s2_red.value)
        .map_err(|e| format!("Detected: {}", e))?;

    match bad_verify(&R2, &A2, &s1, &e1, &g2) {
        Ok(_)    => Ok("No Fiat-Shamir heuristic vulnerability detected.".to_string()),
        Err(err) => Err(format!("Detected: {}", err)),
    }
}

pub fn cross_round_interaction_example() -> Result<String, String> {
    let mut t = TranscriptInspector::new();
    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let g = add_generator(&mut t, "gen", "prover2");

    let msg_rnd = t.add("msg_rnd", "prover", ObjectCategory::Constant,
                        Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let msg = (&g * &msg_rnd).map_err(|e| format!("Detected: {}", e))?;
    let msg = t.add("msg", "prover", ObjectCategory::Message, msg.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let a = t.add("a", "prover", ObjectCategory::Constant,
                  Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let big_a = (&g * &a).map_err(|e| format!("Detected: {}", e))?;
    let big_a = t.add("A", "prover", ObjectCategory::Pubkey, big_a.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let k = t.add("k", "prover", ObjectCategory::Constant,
                  Value::Integer(rand_scalar(&mut rng))).map_err(|e| format!("Detected: {}", e))?;
    let big_r = (&g * &k).map_err(|e| format!("Detected: {}", e))?;
    let big_r = t.add("R", "prover", ObjectCategory::Commitment, big_r.value)
        .map_err(|e| format!("Detected: {}", e))?;

    let mut data = Vec::new();
    data.extend_from_slice(&serialize_tagged(&big_r));
    data.extend_from_slice(&serialize_tagged(&big_a));
    data.extend_from_slice(&serialize_tagged(&msg));
    data.extend_from_slice(&serialize_tagged(&g));
    let e1_val = H(&data, &n);
    let e1 = t.record_challenge("e1", &["A", "R", "msg", "gen"], Value::Integer(e1_val))
        .map_err(|e| format!("Detected: {}", e))?;

    let e1_msg = (&e1 * &msg).map_err(|e| format!("Detected: {}", e))?;
    let z1 = (&big_a - &e1_msg).map_err(|e| format!("Detected: {}", e))?;
    let z1 = t.add("Z1", "prover", ObjectCategory::Response, z1.value)
        .map_err(|e| format!("Detected: {}", e))?;

    data.extend_from_slice(&serialize_tagged(&z1));
    let e2_val = H(&data, &n);
    let e2 = t.record_challenge("e2", &["A", "R", "msg", "gen", "Z1"], Value::Integer(e2_val))
        .map_err(|e| format!("Detected: {}", e))?;

    let e2_msg = (&e2 * &msg).map_err(|e| format!("Detected: {}", e))?;
    let z2 = (&big_a - &e2_msg).map_err(|e| format!("Detected: {}", e))?;
    t.add("Z2", "prover", ObjectCategory::Response, z2.value)
        .map_err(|e| format!("Detected: {}", e))?;

    match t.check_cross_round_interaction("Z2", "A") {
        Ok(_)    => Ok("No Fiat-Shamir heuristic vulnerability detected.".to_string()),
        Err(err) => Err(format!("Detected: {}", err)),
    }
}

pub fn non_constant_interaction_example() -> Result<String, String> {
    let mut t = TranscriptInspector::new();
    let mut rng = rand::thread_rng();
    let n = secp256k1_order();

    let g = add_generator(&mut t, "gen", "prover1");

    let a1 = rand_scalar(&mut rng);
    let big_a1 = mul_point_scalar(&g, &a1)?;
    let big_a1 = t.add("A1", "prover1", ObjectCategory::Pubkey, big_a1.value)
        .map_err(|e| format!("Detection: {}", e))?;

    let k1 = rand_scalar(&mut rng);
    let big_r1 = mul_point_scalar(&g, &k1)?;
    let big_r1 = t.add("R1", "prover1", ObjectCategory::Commitment, big_r1.value)
        .map_err(|e| format!("Detection: {}", e))?;

    let a2 = rand_scalar(&mut rng);
    let big_a2 = mul_point_scalar(&g, &a2)?;
    let big_a2 = t.add("A2", "prover2", ObjectCategory::Pubkey, big_a2.value)
        .map_err(|e| format!("Detection: {}", e))?;

    let k2 = rand_scalar(&mut rng);
    let big_r2 = mul_point_scalar(&g, &k2)?;
    let big_r2 = t.add("R2", "prover2", ObjectCategory::Commitment, big_r2.value)
        .map_err(|e| format!("Detection: {}", e))?;

    let msg_rnd = rand_scalar(&mut rng);
    let msg = mul_point_scalar(&g, &msg_rnd)?;
    let msg = t.add("message", "prover2", ObjectCategory::Message, msg.value)
        .map_err(|e| format!("Detection: {}", e))?;

    let mut data = Vec::new();
    data.extend_from_slice(&serialize_tagged(&big_a1));
    data.extend_from_slice(&serialize_tagged(&big_r1));
    data.extend_from_slice(&serialize_tagged(&big_a2));
    data.extend_from_slice(&serialize_tagged(&big_r2));
    data.extend_from_slice(&serialize_tagged(&msg));
    data.extend_from_slice(&serialize_tagged(&g));
    let e_val = H(&data, &n);
    t.record_challenge("e", &["A1", "A2", "R1", "R2", "message", "gen"], Value::Integer(e_val))
        .map_err(|e| format!("Detection: {}", e))?;

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
    #[test] fn non_const_ok() { assert!(non_constant_interaction_example().is_ok()); }
}
