use std::collections::{HashMap, HashSet};
use std::fmt;
use sha2::{Sha256, Digest};
use uuid::Uuid;
use num_bigint::BigInt;
use num_traits::{Zero, One, Signed};
use num_integer::Integer;
use k256::{ProjectivePoint, Scalar, AffinePoint};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;


#[derive(Debug)]
pub enum TranscriptError {
    ElementAddedAfterChallenge(String, String),
    UnknownElementInChallenge(String, String),
    PlaintextNotInFirstChallenge,
    GeneratorNotInFirstChallenge,
    NotEveryProverMessagesIncluded,
    DuplicateElementsInChallenge,
    DifferentTranscripts,
    TypeError(String),
    UnsafeCrossRoundInteraction(String, String),
}

impl fmt::Display for TranscriptError {fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TranscriptError::ElementAddedAfterChallenge(name, category) => write!(
                f,
                "Element '{}' (category={}) was added after the first challenge and was not included in that challenge.",
                name, category
            ),
            TranscriptError::UnknownElementInChallenge(challenge_name, element_name) => write!(
                f, "Challenge '{}' uses unknown element '{}'!", challenge_name, element_name
            ),
            TranscriptError::PlaintextNotInFirstChallenge => write!(f, "Plaintext was not included in the first challenge!"),
            TranscriptError::GeneratorNotInFirstChallenge => write!(f, "Generator-element was not included in the first challenge!"),
            TranscriptError::NotEveryProverMessagesIncluded => write!(f, "Not every prover's message was included in the challenge!"),
            TranscriptError::DuplicateElementsInChallenge => write!(f, "Challenge has duplicate objects to hash!"),
            TranscriptError::TypeError(msg) => write!(f, "{}", msg),
            TranscriptError::DifferentTranscripts => write!(f, "Objects from different transcripts cannot interact!"),
            TranscriptError::UnsafeCrossRoundInteraction(o1, o2) => write!(f, "Objects '{}' and '{}' from different rounds interact ...", o1, o2),
        }
    }
}

impl std::error::Error for TranscriptError {}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectCategory {
    Commitment, 
    Pubkey, 
    Message, 
    Challenge, 
    Response, 
    Generator, 
    Constant,
}

impl fmt::Display for ObjectCategory {fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ObjectCategory::Commitment => "commitment",
            ObjectCategory::Pubkey => "pubkey",
            ObjectCategory::Message => "message",
            ObjectCategory::Challenge => "challenge",
            ObjectCategory::Response => "response",
            ObjectCategory::Generator => "generator",
            ObjectCategory::Constant => "const",
        };
        write!(f, "{}", s)
    }
}


#[derive(Debug, Clone)]
pub enum Value {
    Integer(BigInt),
    Point(ProjectivePoint),
    List(Vec<Value>),
}

impl PartialEq for Value {fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Integer(a), Value::Integer(b)) => a == b,
            (Value::Point(a), Value::Point(b)) => a == b,
            (Value::List(a), Value::List(b)) => a == b,
            _ => false,
        }
    }
}

impl Value {
    pub fn int<I: Into<BigInt>>(v: I) -> Self { Value::Integer(v.into()) }
    pub fn point(p: ProjectivePoint) -> Self { Value::Point(p) }
}


pub fn secp256k1_order() -> BigInt {
    BigInt::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
    ).unwrap()
}

pub fn secp256k1_field() -> BigInt {
    BigInt::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16
    ).unwrap()
}

pub fn bigint_to_scalar(n: &BigInt) -> Scalar {
    let order = secp256k1_order();
    let reduced = n.mod_floor(&order);
    let (_, mut bytes) = reduced.to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    let arr: [u8; 32] = bytes.try_into().expect("scalar must be 32 bytes after reduction");
    let fb = k256::FieldBytes::from(arr);
    Option::<Scalar>::from(Scalar::from_repr(fb))
        .expect("valid scalar bytes after reduction")
}

pub fn point_xy_bytes(p: &ProjectivePoint) -> Option<([u8; 32], [u8; 32])> {
    let aff: AffinePoint = p.to_affine();
    let enc = aff.to_encoded_point(false);
    if enc.is_identity() { return None; }
    let x = enc.x()?;
    let y = enc.y()?;
    let mut xa = [0u8; 32]; xa.copy_from_slice(x);
    let mut ya = [0u8; 32]; ya.copy_from_slice(y);
    Some((xa, ya))
}

pub fn bigint_to_be32(v: &BigInt) -> [u8; 32] {
    let p = secp256k1_field();
    let reduced = v.mod_floor(&p);
    let (_, bytes) = reduced.to_bytes_be();
    let mut out = [0u8; 32];
    let off = 32 - bytes.len();
    out[off..].copy_from_slice(&bytes);
    out
}

pub fn serialize_tagged(tv: &TaggedValue) -> Vec<u8> {
    match &tv.value {
        Value::Point(p) => match point_xy_bytes(p) {
            Some((x, y)) => {
                let mut out = Vec::with_capacity(64);
                out.extend_from_slice(&x);
                out.extend_from_slice(&y);
                out
            }
            None => vec![0u8; 64],
        },
        Value::Integer(b) => {
            let bytes = bigint_to_be32(b);
            let mut out = Vec::with_capacity(64);
            out.extend_from_slice(&bytes);
            out.extend_from_slice(&bytes);
            out
        }
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone)]
pub struct TaggedValue {
    pub value: Value,
    pub transcript_id: Uuid,
}

impl TaggedValue {
    pub fn new(value: Value, transcript_id: Uuid) -> Self { Self { value, transcript_id } }

    fn ensure_same_transcript_id(&self, other: &TaggedValue) -> Result<(), TranscriptError> {
        if self.transcript_id != other.transcript_id {
            Err(TranscriptError::DifferentTranscripts)
        } else { Ok(()) }
    }

    pub fn as_bigint(&self) -> Option<&BigInt> {
        if let Value::Integer(b) = &self.value { Some(b) } else { None }
    }

    pub fn as_point(&self) -> Option<&ProjectivePoint> {
        if let Value::Point(p) = &self.value { Some(p) } else { None }
    }

    pub fn as_list(&self) -> Option<&Vec<Value>> {
        if let Value::List(v) = &self.value { Some(v) } else { None }
    }

    pub fn index(&self, i: usize) -> TaggedValue {
        match &self.value {
            Value::List(v) => TaggedValue::new(v[i].clone(), self.transcript_id),
            _ => panic!("TaggedValue is not indexable!"),
        }
    }

    pub fn modulo(&self, modulus: &TaggedValue) -> Result<TaggedValue, TranscriptError> {
        self.ensure_same_transcript_id(modulus)?;
        match (&self.value, &modulus.value) {
            (Value::Integer(a), Value::Integer(m)) => {
                Ok(TaggedValue::new(Value::Integer(a.mod_floor(m)), self.transcript_id))
            }
            _ => Err(TranscriptError::TypeError("Modulo only on Integer".into())),
        }
    }

    pub fn modpow(&self, exp: &BigInt, modulus: &BigInt) -> Result<TaggedValue, TranscriptError> {
        match &self.value {
            Value::Integer(b) => {
                let val = if exp.is_negative() {
                    let inv = mod_inverse(b, modulus).ok_or_else(||
                        TranscriptError::TypeError("No modular inverse!".into()))?;
                    inv.modpow(&(-exp), modulus)
                } else {
                    b.modpow(exp, modulus)
                };
                Ok(TaggedValue::new(Value::Integer(val), self.transcript_id))
            }
            _ => Err(TranscriptError::TypeError("Pow only on Integer!".into())),
        }
    }
}

pub fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (g, x, _) = extended_gcd(a.mod_floor(m), m.clone());
    if !g.is_one() { None } else { Some(x.mod_floor(m)) }
}

fn extended_gcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() { (b, BigInt::zero(), BigInt::one()) }
    else {
        let (g, x1, y1) = extended_gcd(b.mod_floor(&a), a.clone());
        let x = y1 - (b / &a) * &x1;
        (g, x, x1)
    }
}

impl<'a, 'b> std::ops::Add<&'b TaggedValue> for &'a TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;
    fn add(self, other: &'b TaggedValue) -> Self::Output {
        self.ensure_same_transcript_id(other)?;
        let v = match (&self.value, &other.value) {
            (Value::Integer(a), Value::Integer(b)) => Value::Integer(a + b),
            (Value::Point(a), Value::Point(b)) => Value::Point(*a + *b),
            _ => return Err(TranscriptError::TypeError("Unsupported types for addition!".into())),
        };
        Ok(TaggedValue::new(v, self.transcript_id))
    }
}

impl<'a, 'b> std::ops::Sub<&'b TaggedValue> for &'a TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;
    fn sub(self, other: &'b TaggedValue) -> Self::Output {
        self.ensure_same_transcript_id(other)?;
        let v = match (&self.value, &other.value) {
            (Value::Integer(a), Value::Integer(b)) => Value::Integer(a - b),
            (Value::Point(a), Value::Point(b)) => Value::Point(*a - *b),
            _ => return Err(TranscriptError::TypeError("Unsupported types for substraction!".into())),
        };
        Ok(TaggedValue::new(v, self.transcript_id))
    }
}

impl<'a, 'b> std::ops::Mul<&'b TaggedValue> for &'a TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;
    fn mul(self, other: &'b TaggedValue) -> Self::Output {
        self.ensure_same_transcript_id(other)?;
        let v = match (&self.value, &other.value) {
            (Value::Integer(a), Value::Integer(b)) => Value::Integer(a * b),
            (Value::Integer(a), Value::Point(p)) => {
                Value::Point(*p * bigint_to_scalar(a))
            }
            (Value::Point(p), Value::Integer(a)) => {
                Value::Point(*p * bigint_to_scalar(a))
            }
            _ => return Err(TranscriptError::TypeError("Unsupported types for multiplication!".into())),
        };
        Ok(TaggedValue::new(v, self.transcript_id))
    }
}

#[derive(Debug, Clone)]
struct TranscriptElement {
    subject: String,
    category: ObjectCategory,
    index: usize,
    round: usize,
    tagged_value: TaggedValue,
}

pub struct TranscriptInspector {
    transcript_id: Uuid,
    elements: HashMap<String, TranscriptElement>,
    challenges: HashMap<String, HashSet<String>>,
    index: usize,
    round: usize,
    challenges_mul: HashMap<String, HashSet<String>>,
    constant_num: usize,
}

impl TranscriptInspector {
    pub fn new() -> Self {
        Self {
            transcript_id: Uuid::new_v4(),
            elements: HashMap::new(),
            challenges: HashMap::new(),
            index: 0, 
            round: 0,
            challenges_mul: HashMap::new(),
            constant_num: 0,
        }
    }

    pub fn get_transcript_id(&self) -> Uuid {
        self.transcript_id
    }

    fn tag(&self, value: Value) -> TaggedValue {
        TaggedValue::new(value, self.transcript_id)
    }

    pub fn add(&mut self, name: &str, subject: &str, category: ObjectCategory, value: Value) -> Result<TaggedValue, TranscriptError> {
        if let Some(e) = self.elements.get(name) {
            return Ok(e.tagged_value.clone());
        }
        if matches!(category, ObjectCategory::Commitment | ObjectCategory::Pubkey)
            && !self.challenges.is_empty()
        {
            return Err(TranscriptError::ElementAddedAfterChallenge(
                name.to_string(), category.to_string()));
        }
        let tagged = self.tag(value);
        self.elements.insert(name.to_string(), TranscriptElement {
            subject: subject.to_string(),
            category, index: self.index, round: self.round,
            tagged_value: tagged.clone(),
        });
        if category == ObjectCategory::Constant { self.constant_num += 1; }
        self.index += 1;
        self.challenges_mul.insert(name.to_string(), HashSet::new());
        Ok(tagged)
    }

    pub fn record_challenge(&mut self, challenge_name: &str, used_names: &[&str], value: Value) -> Result<TaggedValue, TranscriptError> {
        let used_set: HashSet<String> = used_names.iter().map(|s| s.to_string()).collect();
        if used_set.len() != used_names.len() {
            return Err(TranscriptError::DuplicateElementsInChallenge);
        }
        let expected = self.elements.len() - self.challenges.len() - self.constant_num;
        if used_names.len() < expected {
            return Err(TranscriptError::NotEveryProverMessagesIncluded);
        }
        let mut pt_found = false;
        let mut gen_found = false;
        for n in &used_set {
            match self.elements.get(n) {
                Some(info) => {
                    if info.category == ObjectCategory::Message { pt_found = true; }
                    else if info.category == ObjectCategory::Generator { gen_found = true; }
                }
                None => return Err(TranscriptError::UnknownElementInChallenge(
                    challenge_name.to_string(), n.clone())),
            }
        }
        if self.challenges.is_empty() {
            if !pt_found { return Err(TranscriptError::PlaintextNotInFirstChallenge); }
            if !gen_found { return Err(TranscriptError::GeneratorNotInFirstChallenge); }
        }
        let tagged = self.add(challenge_name, "verifier", ObjectCategory::Challenge, value)?;
        self.challenges.insert(challenge_name.to_string(), used_set);
        self.round += 1;
        Ok(tagged)
    }

    pub fn check_cross_round_interaction(&self, object1: &str, object2: &str) -> Result<(), TranscriptError> {
        let info1 = self.elements.get(object1).ok_or_else(||
            TranscriptError::UnsafeCrossRoundInteraction(object1.into(), object2.into()))?;
        let info2 = self.elements.get(object2).ok_or_else(||
            TranscriptError::UnsafeCrossRoundInteraction(object1.into(), object2.into()))?;
        if info1.round == info2.round { return Ok(()); }
        let mul_1 = self.challenges_mul.get(object1).cloned().unwrap_or_default();
        let mul_2 = self.challenges_mul.get(object2).cloned().unwrap_or_default();
        let other_round_challenges_1: HashSet<String> = self.challenges.iter()
            .filter(|(name, _)| self.elements.get(*name).map_or(false, |e| e.round == info2.round))
            .map(|(n, _)| n.clone()).collect();
        let other_round_challenges_2: HashSet<String> = self.challenges.iter()
            .filter(|(name, _)| self.elements.get(*name).map_or(false, |e| e.round == info1.round))
            .map(|(n, _)| n.clone()).collect();
        let safe_1 = !mul_1.is_disjoint(&other_round_challenges_1);
        let safe_2 = !mul_2.is_disjoint(&other_round_challenges_2);
        if !(safe_1 || safe_2) {
            Err(TranscriptError::UnsafeCrossRoundInteraction(object1.into(), object2.into()))
        } else { Ok(()) }
    }
}

impl Default for TranscriptInspector { fn default() -> Self { Self::new() } }

#[allow(non_snake_case)]
pub fn H(data: &[u8], curve_order: &BigInt) -> BigInt {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let val = BigInt::from_bytes_be(num_bigint::Sign::Plus, &digest);
    val.mod_floor(curve_order)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let n = secp256k1_order();
        let h = H(b"Hello!", &n);
        assert!(h >= BigInt::zero());
        assert!(h < n);
    }

    #[test]
    fn test_scalar_mul_point() {
        let g = ProjectivePoint::GENERATOR;
        let s = bigint_to_scalar(&BigInt::from(2));
        let double = g * s;
        let double_prime = g + g;
        assert_eq!(double, double_prime);
    }

    #[test]
    fn test_tagged_ops() {
        let insp = TranscriptInspector::new();
        let id = insp.get_transcript_id();
        let g = TaggedValue::new(Value::Point(ProjectivePoint::GENERATOR), id);
        let s = TaggedValue::new(Value::Integer(BigInt::from(3)), id);
        let prod = (&s * &g).unwrap();
        let prod2 = (&g * &s).unwrap();
        assert_eq!(prod.value, prod2.value);
    }

    #[test]
    fn test_cross_transcript_error() {
        let a = TranscriptInspector::new();
        let b = TranscriptInspector::new();
        let v1 = TaggedValue::new(Value::Integer(BigInt::from(1)), a.get_transcript_id());
        let v2 = TaggedValue::new(Value::Integer(BigInt::from(2)), b
        .get_transcript_id());
        assert!((&v1 + &v2).is_err());
    }
}
