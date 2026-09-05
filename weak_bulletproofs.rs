// example of bulletproofs implementing weak Fiat-Shamir heuristics

use std::collections::HashMap;
use rand::Rng;
use sha3::Sha3_256;
use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, ToPrimitive, Zero};
use num_integer::Integer;
use crate::poc::{
    mod_inverse, TranscriptInspector, Value,
};


fn p_modulus() -> BigInt {
    (BigInt::one() << 255) - BigInt::from(19)
}
fn q_order() -> BigInt {
    (BigInt::one() << 127) - BigInt::one()
}

fn gexp(b: &BigInt, e: &BigInt) -> BigInt {
    let q = q_order();
    let p = p_modulus();
    let exp = e.mod_floor(&q);
    if exp.is_zero() {
        BigInt::one()
    } else {
        b.modpow(&exp, &p)
    }
}

fn rand_q(rng: &mut impl Rng) -> BigInt {
    let q = q_order();
    rng.gen_bigint_range(&BigInt::zero(), &q)
}

fn extract_int(v: &Value, name: &str) -> Result<BigInt, String> {
    match v {
        Value::Integer(b) => Ok(b.clone()),
        _ => Err(format!("Invalid {} parameter (expected Integer)", name)),
    }
}
fn extract_list(v: &Value, name: &str) -> Result<Vec<BigInt>, String> {
    match v {
        Value::List(items) => items.iter().enumerate().map(|(i, x)| match x {
            Value::Integer(b) => Ok(b.clone()),
            _ => Err(format!("Invalid {}[{}] (expected Integer)", name, i)),
        }).collect(),
        _ => Err(format!("Invalid {} parameter (expected List)", name)),
    }
}

pub fn setup(m: i64, n: i64) -> HashMap<String, Value> {
    let mut rng = rand::thread_rng();
    let q = q_order();
    let mut params = HashMap::new();
    params.insert("m".to_string(), Value::Integer(BigInt::from(m)));
    params.insert("n".to_string(), Value::Integer(BigInt::from(n)));

    let mn = (m * n) as usize;
    let g_vec: Vec<Value> = (0..mn).map(|_| Value::Integer(rng.gen_bigint_range(&BigInt::zero(), &q))).collect();
    let h_vec: Vec<Value> = (0..mn).map(|_| Value::Integer(rng.gen_bigint_range(&BigInt::zero(), &q))).collect();
    params.insert("g_vec".to_string(), Value::List(g_vec));
    params.insert("h_vec".to_string(), Value::List(h_vec));
    params.insert("g".to_string(), Value::Integer(rng.gen_bigint_range(&BigInt::zero(), &q)));
    params.insert("h".to_string(), Value::Integer(rng.gen_bigint_range(&BigInt::zero(), &q)));
    params.insert("u".to_string(), Value::Integer(rng.gen_bigint_range(&BigInt::zero(), &q)));
    params
}

fn delta(y: &BigInt, z: &BigInt, m: i64, n: i64) -> BigInt {
    let q = q_order();
    let mut sum_y = BigInt::zero();
    let mut y_exp = BigInt::one();
    for _ in 0..n {
        sum_y = (&sum_y + &y_exp).mod_floor(&q);
        y_exp = (&y_exp * y).mod_floor(&q);
    }

    let two = BigInt::from(2);
    let sum_2 = (two.modpow(&BigInt::from(n as u64), &q) - BigInt::one()).mod_floor(&q);

    let mut sum_z = BigInt::zero();
    for j in 1..=m {
        let z_pow = z.modpow(&BigInt::from((j + 2) as u64), &q);
        sum_z = (&sum_z + (&z_pow * &sum_2).mod_floor(&q)).mod_floor(&q);
    }

    let z2 = z.modpow(&BigInt::from(2), &q);
    let term = ((z - &z2).mod_floor(&q) * &sum_y).mod_floor(&q);
    (term - sum_z).mod_floor(&q)
}

pub fn forge_bulletproof(params: &HashMap<String, Value>) -> Result<HashMap<String, Value>, String> {
    let mut t = TranscriptInspector::new(b"forged_transcript");
    let mut rng = rand::thread_rng();
    let p = p_modulus();
    let q = q_order();

    let m_bi = extract_int(params.get("m").ok_or("missing m")?, "m")?;
    let n_bi = extract_int(params.get("n").ok_or("missing n")?, "n")?;
    let m = m_bi.to_i64().ok_or("m out of range")?;
    let n = n_bi.to_i64().ok_or("n out of range")?;

    let g_vec = extract_list(params.get("g_vec").ok_or("missing g_vec")?, "g_vec")?;
    let h_vec = extract_list(params.get("h_vec").ok_or("missing h_vec")?, "h_vec")?;
    let g = extract_int(params.get("g").ok_or("missing g")?, "g")?;
    let h = extract_int(params.get("h").ok_or("missing h")?, "h")?;
    let u = extract_int(params.get("u").ok_or("missing u")?, "u")?;

    let to_list = |values: &[BigInt]| {
        Value::List(values.iter().cloned().map(Value::Integer).collect())
    };

    t.add_public_key("m", Value::Integer(m_bi)).map_err(|e| e.to_string())?;
    t.add_public_key("n", Value::Integer(n_bi)).map_err(|e| e.to_string())?;
    t.add_public_key("g_vec", to_list(&g_vec)).map_err(|e| e.to_string())?;
    t.add_public_key("h_vec", to_list(&h_vec)).map_err(|e| e.to_string())?;
    t.add_generator_for("g", "prover", Value::Integer(g.clone())).map_err(|e| e.to_string())?;
    t.add_generator_for("h", "prover", Value::Integer(h.clone())).map_err(|e| e.to_string())?;
    t.add_generator_for("u", "prover", Value::Integer(u.clone())).map_err(|e| e.to_string())?;
    t.add_generator_for("p", "prover", Value::Integer(p.clone())).map_err(|e| e.to_string())?;
    t.add_generator_for("q", "prover", Value::Integer(q.clone())).map_err(|e| e.to_string())?;

    let a_l: Vec<BigInt> = (0..n).map(|_| BigInt::from(rng.gen_range(0..2u8))).collect();
    let a_r: Vec<BigInt> = a_l.iter().map(|a| (a - BigInt::one()).mod_floor(&q)).collect();
    let s_l: Vec<BigInt> = (0..n).map(|_| rand_q(&mut rng)).collect();
    let s_r: Vec<BigInt> = (0..n).map(|_| rand_q(&mut rng)).collect();
    let alpha = rand_q(&mut rng);
    let ro = rand_q(&mut rng);

    t.add_constant("a_L", to_list(&a_l)).map_err(|e| e.to_string())?;
    t.add_constant("a_R", to_list(&a_r)).map_err(|e| e.to_string())?;
    t.add_constant("s_L", to_list(&s_l)).map_err(|e| e.to_string())?;
    t.add_constant("s_R", to_list(&s_r)).map_err(|e| e.to_string())?;
    t.add_constant("alpha", Value::Integer(alpha.clone())).map_err(|e| e.to_string())?;
    t.add_constant("ro", Value::Integer(ro.clone())).map_err(|e| e.to_string())?;

    let mut big_a = gexp(&h, &alpha);
    let mut big_s = gexp(&h, &ro);
    for i in 0..n as usize {
        big_a = (&big_a * gexp(&g_vec[i], &a_l[i])).mod_floor(&p);
        big_a = (&big_a * gexp(&h_vec[i], &a_r[i])).mod_floor(&p);
        big_s = (&big_s * gexp(&g_vec[i], &s_l[i])).mod_floor(&p);
        big_s = (&big_s * gexp(&h_vec[i], &s_r[i])).mod_floor(&p);
    }
    t.add_commitment("A", Value::Integer(big_a.clone())).map_err(|e| e.to_string())?;
    t.add_commitment("S", Value::Integer(big_s.clone())).map_err(|e| e.to_string())?;

    let yz_tags = t
        .record_challenges::<Sha3_256>(&["y", "z"], &["A", "S"], &q)
        .map_err(|e| e.to_string())?;
    let y_tag = yz_tags.first().ok_or("missing y challenge")?;
    let z_tag = yz_tags.get(1).ok_or("missing z challenge")?;
    let y_val = y_tag.as_bigint().ok_or("y must be Integer")?;
    let z_val = z_tag.as_bigint().ok_or("z must be Integer")?;

    let t1 = rand_q(&mut rng);
    let t2 = rand_q(&mut rng);
    let tau1 = rand_q(&mut rng);
    let tau2 = rand_q(&mut rng);
    t.add_constant("t1", Value::Integer(t1.clone())).map_err(|e| e.to_string())?;
    t.add_constant("t2", Value::Integer(t2.clone())).map_err(|e| e.to_string())?;
    t.add_constant("tau1", Value::Integer(tau1.clone())).map_err(|e| e.to_string())?;
    t.add_constant("tau2", Value::Integer(tau2.clone())).map_err(|e| e.to_string())?;

    let big_t1 = (gexp(&g, &t1) * gexp(&h, &tau1)).mod_floor(&p);
    let big_t2 = (gexp(&g, &t2) * gexp(&h, &tau2)).mod_floor(&p);
    t.add_commitment("T1", Value::Integer(big_t1.clone())).map_err(|e| e.to_string())?;
    t.add_commitment("T2", Value::Integer(big_t2.clone())).map_err(|e| e.to_string())?;

    let x_tag = t.record_challenge::<Sha3_256>("x", &["A", "S", "T1", "T2"], &q).map_err(|e| e.to_string())?;
    let x_val = x_tag.as_bigint().ok_or("x must be Integer")?;

    let l: Vec<BigInt> = (0..n as usize).map(|i| {
        ((&a_l[i] - z_val) + (&s_l[i] * x_val)).mod_floor(&q)
    }).collect();

    let z2 = z_val.modpow(&BigInt::from(2), &q);
    let r: Vec<BigInt> = (0..n as usize).map(|i| {
        let yi = y_val.modpow(&BigInt::from(i as u64), &q);
        let twoi = BigInt::from(2).modpow(&BigInt::from(i as u64), &q);
        let term1 = (&yi * ((&a_r[i] + z_val) + (&s_r[i] * x_val))).mod_floor(&q);
        let term2 = (&z2 * &twoi).mod_floor(&q);
        (term1 + term2).mod_floor(&q)
    }).collect();

    let mut t_hat = BigInt::zero();
    for i in 0..n as usize {
        t_hat = (t_hat + (&l[i] * &r[i]).mod_floor(&q)).mod_floor(&q);
    }
    let mu = (&alpha + &ro * x_val).mod_floor(&q);
    let tau_x = rand_q(&mut rng);

    t.add_constant("l", to_list(&l)).map_err(|e| e.to_string())?;
    t.add_constant("r", to_list(&r)).map_err(|e| e.to_string())?;
    t.add_constant("t_hat", Value::Integer(t_hat.clone())).map_err(|e| e.to_string())?;
    t.add_constant("mu", Value::Integer(mu.clone())).map_err(|e| e.to_string())?;
    t.add_constant("tau_x", Value::Integer(tau_x.clone())).map_err(|e| e.to_string())?;

    let w_tag = t.record_challenge::<Sha3_256>("w", &["A", "S", "T1", "T2", "t_hat", "tau_x", "mu"], &q)
        .map_err(|e| e.to_string())?;
    let w_val = w_tag.as_bigint().ok_or("w must be Integer")?;

    let mn = (m * n) as usize;
    let y_pow = y_val.modpow(&BigInt::from((m * n) as u64), &q);
    let y_inv = mod_inverse(&y_pow, &q).ok_or("y has no inverse mod q")?;
    let h_prime: Vec<BigInt> = (0..mn).map(|i| gexp(&h_vec[i], &y_inv)).collect();
    let u_prime = gexp(&u, w_val);

    let neg_mu = (-&mu).mod_floor(&q);
    let mut p_prime = gexp(&h, &neg_mu);
    p_prime = (&p_prime * &big_a).mod_floor(&p);
    p_prime = (&p_prime * gexp(&big_s, x_val)).mod_floor(&p);
    let neg_z = (-z_val).mod_floor(&q);
    for gi in &g_vec {
        p_prime = (&p_prime * gexp(gi, &neg_z)).mod_floor(&p);
    }
    let mut y_exp = BigInt::one();
    for h in h_prime.iter().take(mn) {
        let exp = (z_val * &y_exp).mod_floor(&q);
        p_prime = (&p_prime * gexp(h, &exp)).mod_floor(&p);
        y_exp = (&y_exp * y_val).mod_floor(&q);
    }
    for j in 1..=m {
        let z_exp = z_val.modpow(&BigInt::from((j + 1) as u64), &q);
        let mut two_exp = BigInt::one();
        for i in 0..n {
            let idx = ((j - 1) * n + i) as usize;
            let exp = (&z_exp * &two_exp).mod_floor(&q);
            p_prime = (&p_prime * gexp(&h_prime[idx], &exp)).mod_floor(&p);
            two_exp = (&two_exp * BigInt::from(2)).mod_floor(&q);
        }
    }
    p_prime = (&p_prime * gexp(&u_prime, &t_hat)).mod_floor(&p);

    t.add_constant("h_prime", to_list(&h_prime)).map_err(|e| e.to_string())?;
    t.add_constant("u_prime", Value::Integer(u_prime)).map_err(|e| e.to_string())?;
    t.add_constant("P_prime", Value::Integer(p_prime)).map_err(|e| e.to_string())?;
    t.add_constant("pi_BP_IPA", Value::List(vec![
        Value::Integer(t_hat.clone()), Value::Integer(mu.clone())
    ])).map_err(|e| e.to_string())?;

    let rhs_v = (&t_hat - &t1 * x_val - &t2 * x_val * x_val - delta(y_val, z_val, m, n)).mod_floor(&q);
    let rhs_g = (&tau_x - &tau1 * x_val - &tau2 * x_val * x_val).mod_floor(&q);

    let mut big_v: Vec<BigInt> = Vec::new();
    for j in 1..=m {
        let (vj, gj) = if j == 1 {
            let z_exp = z_val.modpow(&BigInt::from(2), &q);
            let z_inv = mod_inverse(&z_exp, &q).ok_or("z^2 has no inverse mod q")?;
            ((&rhs_v * &z_inv).mod_floor(&q), (&rhs_g * &z_inv).mod_floor(&q))
        } else {
            (BigInt::zero(), BigInt::zero())
        };
        let vj_pt = (gexp(&g, &vj) * gexp(&h, &gj)).mod_floor(&p);
        big_v.push(vj_pt);
    }
    t.add_constant("V", Value::List(big_v.iter().cloned().map(Value::Integer).collect()))
        .map_err(|e| e.to_string())?;

    let mut proof = HashMap::new();
    proof.insert("V".to_string(), Value::List(big_v.iter().cloned().map(Value::Integer).collect()));
    proof.insert("A".to_string(), Value::Integer(big_a));
    proof.insert("S".to_string(), Value::Integer(big_s));
    proof.insert("T1".to_string(), Value::Integer(big_t1));
    proof.insert("T2".to_string(), Value::Integer(big_t2));
    proof.insert("t_hat".to_string(), Value::Integer(t_hat.clone()));
    proof.insert("tau_x".to_string(), Value::Integer(tau_x));
    proof.insert("mu".to_string(), Value::Integer(mu.clone()));
    proof.insert("PiBP-IPA".to_string(), Value::List(vec![Value::Integer(t_hat), Value::Integer(mu)]));
    Ok(proof)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forged_bulletproofs() {
        let params = setup(23, 17);

        let res = forge_bulletproof(&params);

        if let Err(e) = &res {
            println!("Forgery rejected: {}", e);
        }

        assert!(res.is_err(), "expected detector to reject");
    }

    #[test]
    fn delta_smoke() {
        let y = BigInt::from(5);
        let z = BigInt::from(3);
        let v = delta(&y, &z, 2, 4);
        assert!(v >= BigInt::zero());
    }

    #[test]
    fn gexp_inverse_consistency() {
        let p = p_modulus();
        let b = BigInt::from(7);
        let r = gexp(&b, &BigInt::from(10));
        assert!(r >= BigInt::zero() && r < p);
    }
}
