use std::collections::{HashMap, HashSet};
use std::fmt;
use sha3::Digest;
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

impl fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            TranscriptError::UnsafeCrossRoundInteraction(o1, o2) => write!(f, "Objects '{}' and '{}' from different rounds interact!", o1, o2),
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

impl fmt::Display for ObjectCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
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
    BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap()
}

pub fn secp256k1_field() -> BigInt {
    BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap()
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
    let arr: [u8; 32] = bytes.try_into().expect("Scalar must be 32 bytes after reduction!");
    let fb = k256::FieldBytes::from(arr);
    Option::<Scalar>::from(Scalar::from_repr(fb))
        .expect("Valid scalar bytes after reduction")
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
    pub fn new(value: Value, transcript_id: Uuid) -> Self { 
        Self { 
            value, 
            transcript_id 
        } 
    }

    fn ensure_same_transcript_id(&self, other: &TaggedValue) -> Result<(), TranscriptError> {
        if self.transcript_id != other.transcript_id {
            Err(TranscriptError::DifferentTranscripts)
        } else { Ok(()) }
    }

    pub fn as_bigint(&self) -> Option<&BigInt> {
        if let Value::Integer(b) = &self.value { 
            Some(b) 
        } else { None }
    }

    pub fn as_point(&self) -> Option<&ProjectivePoint> {
        if let Value::Point(p) = &self.value { 
            Some(p) 
        } else { None }
    }

    pub fn as_list(&self) -> Option<&Vec<Value>> {
        if let Value::List(v) = &self.value { 
            Some(v) 
        } else { None }
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
            _ => Err(TranscriptError::TypeError("Modulo only on Integer".to_string())),
        }
    }

    pub fn modpow(&self, exp: &BigInt, modulus: &BigInt) -> Result<TaggedValue, TranscriptError> {
        match &self.value {
            Value::Integer(b) => {
                let val = if exp.is_negative() {
                    let inv = mod_inverse(b, modulus).ok_or_else(||
                        TranscriptError::TypeError("No modular inverse!".to_string()))?;
                    inv.modpow(&(-exp), modulus)
                } else {
                    b.modpow(exp, modulus)
                };
                Ok(TaggedValue::new(Value::Integer(val), self.transcript_id))
            }
            _ => Err(TranscriptError::TypeError("Pow only on Integer!".to_string())),
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
            _ => return Err(TranscriptError::TypeError("Unsupported types for addition!".to_string())),
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
            _ => return Err(TranscriptError::TypeError("Unsupported types for multiplication!".to_string())),
        };
        Ok(TaggedValue::new(v, self.transcript_id))
    }
}

impl std::ops::Add for TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;

    fn add(self, other: TaggedValue) -> Self::Output {
        &self + &other
    }
}

impl std::ops::Sub for TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;

    fn sub(self, other: TaggedValue) -> Self::Output {
        &self - &other
    }
}

impl std::ops::Mul for TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;

    fn mul(self, other: TaggedValue) -> Self::Output {
        &self * &other
    }
}


#[derive(Debug, Clone)]
struct TranscriptElement {
    #[allow(dead_code)] subject: String,
    category: ObjectCategory,
    #[allow(dead_code)] index: usize,
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
    transcript: Vec<u8>,
}


fn serialize_value_into(buf: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Integer(b) => {
            buf.push(0x01);
            buf.extend_from_slice(&bigint_to_be32(b));
        }
        Value::Point(p) => {
            buf.push(0x02);
            match point_xy_bytes(p) {
                Some((x, y)) => {
                    buf.extend_from_slice(&x);
                    buf.extend_from_slice(&y);
                }
                None => buf.extend_from_slice(&[0u8; 64]),
            }
        }
        Value::List(items) => {
            buf.push(0x03);
            buf.extend_from_slice(&(items.len() as u32).to_be_bytes());
            for it in items {
                serialize_value_into(buf, it);
            }
        }
    }
}

impl TranscriptInspector {
    pub fn new() -> Self { 
        Self::with_label(b"") 
    }

    pub fn with_label(protocol_label: &[u8]) -> Self {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&(protocol_label.len() as u32).to_be_bytes());
        transcript.extend_from_slice(protocol_label);
        Self {
            transcript_id: Uuid::new_v4(),
            elements: HashMap::new(),
            challenges: HashMap::new(),
            index: 0,
            round: 0,
            challenges_mul: HashMap::new(),
            constant_num: 0,
            transcript,
        }
    }

    pub fn get_transcript_id(&self) -> Uuid { 
        self.transcript_id 
    }

    fn tag(&self, value: Value) -> TaggedValue { 
        TaggedValue::new(value, self.transcript_id) 
    }

    pub fn transcript_bytes(&self) -> &[u8] { 
        &self.transcript 
    }

    // add object to transcript (who did it, its category (pubkey, challenge, ...), its number in transcript and round number)
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

        let name_bytes = name.as_bytes();
        self.transcript.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
        self.transcript.extend_from_slice(name_bytes);
        self.transcript.push(category as u8 + 0x10);
        serialize_value_into(&mut self.transcript, &value);

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

    fn validate_challenge_batch(
        &self,
        challenge_names: &[&str],
        used_names: &[&str],
        curve_order: &BigInt,
    ) -> Result<HashSet<String>, TranscriptError> {
        if challenge_names.is_empty() {
            return Err(TranscriptError::TypeError(
                "At least one challenge name is required".to_string(),
            ));
        }
        if !curve_order.is_positive() {
            return Err(TranscriptError::TypeError(
                "Curve order must be positive".to_string(),
            ));
        }
        let distinct_challenge_names: HashSet<&str> =
            challenge_names.iter().copied().collect();
        if distinct_challenge_names.len() != challenge_names.len() {
            return Err(TranscriptError::TypeError(
                "Challenge batch contains duplicate names".to_string(),
            ));
        }
        for challenge_name in challenge_names {
            if self.elements.contains_key(*challenge_name) {
                return Err(TranscriptError::TypeError(format!(
                    "Transcript element '{}' already exists",
                    challenge_name,
                )));
            }
        }

        let used_set: HashSet<String> = used_names.iter().map(|s| s.to_string()).collect();
        if used_set.len() != used_names.len() {
            return Err(TranscriptError::DuplicateElementsInChallenge);
        }
        let expected_count = self.elements.values().filter(|e| matches!(
            e.category,
            ObjectCategory::Commitment
                | ObjectCategory::Pubkey
                | ObjectCategory::Message
                | ObjectCategory::Response,
        )).count();
        let referenced_msgs_count = used_set.iter().filter(|n| {
            self.elements.get(*n).is_some_and(|e| matches!(
                e.category,
                ObjectCategory::Commitment
                    | ObjectCategory::Pubkey
                    | ObjectCategory::Message
                    | ObjectCategory::Response,
            ))
        }).count();
        if referenced_msgs_count < expected_count {
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
                None => return Err(TranscriptError::UnknownElementInChallenge( // error if an argument was not declared in transcript
                    challenge_names[0].to_string(), n.clone())),
            }
        }
        if self.challenges.is_empty() {
            if !pt_found { return Err(TranscriptError::PlaintextNotInFirstChallenge); } // error if plaintext was not hashed in the first challenge
            if !gen_found { return Err(TranscriptError::GeneratorNotInFirstChallenge); } // error if generator (of a group or an ellicptic curve) was not hashed in the first challenge
        }

        Ok(used_set)
    }

    /// Create several Fiat-Shamir challenges in one logical protocol round.
    /// The entire batch is validated before the transcript is modified.
    pub fn record_challenges<H: FSHash>(
        &mut self,
        challenge_names: &[&str],
        used_names: &[&str],
        curve_order: &BigInt,
    ) -> Result<Vec<TaggedValue>, TranscriptError> {
        let used_set = self.validate_challenge_batch(
            challenge_names,
            used_names,
            curve_order,
        )?;
        let mut tagged_challenges = Vec::with_capacity(challenge_names.len());
        for challenge_name in challenge_names {
            let mut buf = Vec::with_capacity(self.transcript.len() + challenge_name.len());
            buf.extend_from_slice(&self.transcript);
            buf.extend_from_slice(challenge_name.as_bytes());
            let digest = H::hash(&buf);
            let val = BigInt::from_bytes_be(num_bigint::Sign::Plus, &digest)
                .mod_floor(curve_order);
            let tagged = self.add(
                challenge_name, "verifier",
                ObjectCategory::Challenge, Value::Integer(val),
            )?;
            self.challenges.insert(challenge_name.to_string(), used_set.clone());
            tagged_challenges.push(tagged);
        }
        self.round += 1;
        Ok(tagged_challenges)
    }

    // create one challenge and finish the current logical round
    pub fn record_challenge<H: FSHash>(&mut self, challenge_name: &str, used_names: &[&str], curve_order: &BigInt) -> Result<TaggedValue, TranscriptError> {
        self.record_challenges::<H>(&[challenge_name], used_names, curve_order)?
            .into_iter()
            .next()
            .ok_or_else(|| TranscriptError::TypeError(
                "Challenge generation returned no value".to_string(),
            ))
    }

    /// record that a transcript element was multiplied by a challenge
    pub fn record_challenge_multiplication(
        &mut self,
        element_name: &str,
        challenge_name: &str,
    ) -> Result<(), TranscriptError> {
        let element = self.elements.get(element_name).ok_or_else(|| {
            TranscriptError::TypeError(format!(
                "Unknown transcript element '{}'",
                element_name,
            ))
        })?;
        let challenge = self.elements.get(challenge_name).ok_or_else(|| {
            TranscriptError::TypeError(format!(
                "Unknown challenge '{}'",
                challenge_name,
            ))
        })?;
        if challenge.category != ObjectCategory::Challenge {
            return Err(TranscriptError::TypeError(format!(
                "Element '{}' is not a challenge",
                challenge_name,
            )));
        }
        if challenge.round >= element.round {
            return Err(TranscriptError::UnsafeCrossRoundInteraction(
                element_name.to_string(),
                challenge_name.to_string(),
            ));
        }
        self.challenges_mul
            .get_mut(element_name)
            .expect("Every transcript element has challenge metadata")
            .insert(challenge_name.to_string());
        Ok(())
    }

    /// Add a prover response and atomically register the challenges used to
    /// construct it. Validation happens before the transcript is changed.
    pub fn add_response(
        &mut self,
        name: &str,
        value: Value,
        challenge_names: &[&str],
    ) -> Result<TaggedValue, TranscriptError> {
        if self.elements.contains_key(name) {
            return Err(TranscriptError::TypeError(format!(
                "Transcript element '{}' already exists",
                name,
            )));
        }
        for challenge_name in challenge_names {
            let challenge = self.elements.get(*challenge_name).ok_or_else(|| {
                TranscriptError::TypeError(format!(
                    "Unknown challenge '{}'",
                    challenge_name,
                ))
            })?;
            if challenge.category != ObjectCategory::Challenge {
                return Err(TranscriptError::TypeError(format!(
                    "Element '{}' is not a challenge",
                    challenge_name,
                )));
            }
            if challenge.round >= self.round {
                return Err(TranscriptError::UnsafeCrossRoundInteraction(
                    name.to_string(),
                    (*challenge_name).to_string(),
                ));
            }
        }

        let tagged = self.add(name, "prover", ObjectCategory::Response, value)?;
        let multiplications = self
            .challenges_mul
            .get_mut(name)
            .expect("Every transcript element has challenge metadata");
        multiplications.extend(challenge_names.iter().map(|name| (*name).to_string()));
        Ok(tagged)
    }

    // detect errors in cross-round interaction
    pub fn check_cross_round_interaction(
        &self, object1: &str, object2: &str,
    ) -> Result<(), TranscriptError> {
        let info1 = self.elements.get(object1).ok_or_else(||
            TranscriptError::UnsafeCrossRoundInteraction(object1.into(), object2.into()))?;
        let info2 = self.elements.get(object2).ok_or_else(||
            TranscriptError::UnsafeCrossRoundInteraction(object1.into(), object2.into()))?;
        if info1.round == info2.round { return Ok(()); }
        let mul_1 = self.challenges_mul.get(object1).cloned().unwrap_or_default(); // list of challenges object1 was multiplied by
        let mul_2 = self.challenges_mul.get(object2).cloned().unwrap_or_default(); // list of challenges object2 was multiplied by
        let other_round_challenges_1: HashSet<String> = self.challenges.iter()
            .filter(|(name, _)| self.elements.get(*name).map_or(false, |e| e.round == info2.round))
            .map(|(n, _)| n.clone()).collect(); // list of challenges in round of object2
        let other_round_challenges_2: HashSet<String> = self.challenges.iter()
            .filter(|(name, _)| self.elements.get(*name).map_or(false, |e| e.round == info1.round))
            .map(|(n, _)| n.clone()).collect(); // list of challenges in round of object1
        let safe_1 = !mul_1.is_disjoint(&other_round_challenges_1); // check if object1 was multiplied by any challenge in round of object2
        let safe_2 = !mul_2.is_disjoint(&other_round_challenges_2); // check if object2 was multiplied by any challenge in round of object1
        if !(safe_1 || safe_2) {
            Err(TranscriptError::UnsafeCrossRoundInteraction(object1.into(), object2.into()))
        } else { Ok(()) }
    }
}

impl Default for TranscriptInspector { fn default() -> Self { Self::new() } }

// allow using arbitrary hash-function compatible to Digest
pub trait FSHash {
    fn hash(input: &[u8]) -> Vec<u8>;
}

impl<D: Digest> FSHash for D {
    fn hash(input: &[u8]) -> Vec<u8> {
        let mut h = <D as Digest>::new();
        h.update(input);
        h.finalize().to_vec()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_mul_real_curve() {
        let g = ProjectivePoint::GENERATOR;
        let s = bigint_to_scalar(&BigInt::from(2));
        let two_g = g * s;
        let g_plus_g = g + g;
        assert_eq!(two_g, g_plus_g);
    }

    #[test]
    fn test_tagged_arithmetic_points() {
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

    #[test]
    fn cross_round_interaction_is_safe_after_challenge_multiplication() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_label(b"cross-round-safe");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        transcript.add("z", "prover", ObjectCategory::Response, Value::int(5)).unwrap();
        transcript.record_challenge_multiplication("z", "e").unwrap();

        assert!(transcript.check_cross_round_interaction("z", "g").is_ok());
    }

    #[test]
    fn cross_round_interaction_without_challenge_multiplication_is_rejected() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_label(b"cross-round-unsafe");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        transcript.add("z", "prover", ObjectCategory::Response, Value::int(5)).unwrap();

        assert!(matches!(
            transcript.check_cross_round_interaction("z", "g"),
            Err(TranscriptError::UnsafeCrossRoundInteraction(_, _))
        ));
    }

    #[test]
    fn challenge_multiplication_rejects_non_challenge_elements() {
        let mut transcript = TranscriptInspector::with_label(b"cross-round-invalid-challenge");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("z", "prover", ObjectCategory::Response, Value::int(5)).unwrap();

        assert!(matches!(
            transcript.record_challenge_multiplication("z", "g"),
            Err(TranscriptError::TypeError(_))
        ));
    }

    #[test]
    fn owned_tagged_values_support_natural_rust_operators() {
        let transcript = TranscriptInspector::new();
        let e = transcript.tag(Value::int(7));
        let message = transcript.tag(Value::int(3));
        let public_key = transcript.tag(Value::int(29));

        let e_msg = (e * message).unwrap();
        let response = (public_key - e_msg).unwrap();

        assert_eq!(response.as_bigint(), Some(&BigInt::from(8)));
    }

    #[test]
    fn add_response_registers_challenge_multiplication_atomically() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_label(b"response-api");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        transcript.add_response("z", Value::int(5), &["e"]).unwrap();

        assert!(transcript.check_cross_round_interaction("z", "g").is_ok());
    }

    #[test]
    fn add_response_does_not_mutate_transcript_when_challenge_is_invalid() {
        let mut transcript = TranscriptInspector::with_label(b"response-api-invalid");
        let before = transcript.transcript_bytes().to_vec();

        assert!(transcript.add_response("z", Value::int(5), &["missing"]).is_err());
        assert_eq!(transcript.transcript_bytes(), before);
        assert!(!transcript.elements.contains_key("z"));
    }

    #[test]
    fn add_response_rejects_name_of_an_existing_non_response() {
        let mut transcript = TranscriptInspector::with_label(b"response-name-collision");
        transcript.add("z", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        let before = transcript.transcript_bytes().to_vec();

        assert!(matches!(
            transcript.add_response("z", Value::int(5), &[]),
            Err(TranscriptError::TypeError(_))
        ));
        assert_eq!(transcript.transcript_bytes(), before);
    }

    #[test]
    fn add_response_rejects_repeated_response_name() {
        let mut transcript = TranscriptInspector::with_label(b"repeated-response-name");
        transcript.add_response("z", Value::int(5), &[]).unwrap();
        let before = transcript.transcript_bytes().to_vec();

        assert!(matches!(
            transcript.add_response("z", Value::int(7), &[]),
            Err(TranscriptError::TypeError(_))
        ));
        assert_eq!(transcript.transcript_bytes(), before);
        assert_eq!(transcript.elements["z"].tagged_value.as_bigint(), Some(&BigInt::from(5)));
    }

    #[test]
    fn several_challenges_can_belong_to_one_round() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_label(b"same-round-challenges");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();

        let challenges = transcript
            .record_challenges::<Sha3_256>(&["y", "z"], &["g", "m"], &BigInt::from(97))
            .unwrap();

        assert_eq!(challenges.len(), 2);
        assert_eq!(transcript.elements["y"].round, 0);
        assert_eq!(transcript.elements["z"].round, 0);
        assert_eq!(transcript.round, 1);

        transcript.add_response("response", Value::int(5), &["z"]).unwrap();
        assert!(transcript.check_cross_round_interaction("response", "g").is_ok());
    }

    #[test]
    fn test_multi_round_interaction() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_label(b"non-adjacent-rounds");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        transcript
            .record_challenges::<Sha3_256>(&["y", "z"], &["g", "m"], &BigInt::from(97))
            .unwrap();
        transcript.add_response("r1", Value::int(5), &["y", "z"]).unwrap();
        transcript
            .record_challenge::<Sha3_256>("x", &["g", "m", "r1"], &BigInt::from(97))
            .unwrap();
        transcript.add_response("r2", Value::int(7), &["x"]).unwrap();

        assert!(transcript.check_cross_round_interaction("r2", "r1").is_ok());
        assert!(matches!(
            transcript.check_cross_round_interaction("r2", "g"),
            Err(TranscriptError::UnsafeCrossRoundInteraction(_, _))
        ));

        transcript.record_challenge_multiplication("r2", "y").unwrap();
        assert!(transcript.check_cross_round_interaction("r2", "g").is_ok());
    }

    #[test]
    fn cross_round_check_supports_an_arbitrary_number_of_rounds() {
        use sha3::Sha3_256;

        const ROUND_COUNT: usize = 32;
        let mut transcript = TranscriptInspector::with_label(b"arbitrary-round-count");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        let mut prover_elements = vec!["g".to_string(), "m".to_string()];

        for round in 0..ROUND_COUNT {
            let challenge_name = format!("e_{round}");
            let response_name = format!("r_{round}");
            let used_names: Vec<&str> = prover_elements.iter().map(String::as_str).collect();
            transcript
                .record_challenge::<Sha3_256>(
                    &challenge_name,
                    &used_names,
                    &BigInt::from(97),
                )
                .unwrap();
            transcript
                .add_response(
                    &response_name,
                    Value::int(round + 5),
                    &[challenge_name.as_str()],
                )
                .unwrap();

            let previous_round_object = if round == 0 {
                "g"
            } else {
                prover_elements.last().unwrap().as_str()
            };
            assert!(transcript
                .check_cross_round_interaction(&response_name, previous_round_object)
                .is_ok());
            prover_elements.push(response_name);
        }

        let final_response = format!("r_{}", ROUND_COUNT - 1);
        assert_eq!(transcript.round, ROUND_COUNT);
        assert!(matches!(
            transcript.check_cross_round_interaction(&final_response, "g"),
            Err(TranscriptError::UnsafeCrossRoundInteraction(_, _))
        ));

        transcript
            .record_challenge_multiplication(&final_response, "e_0")
            .unwrap();
        assert!(transcript
            .check_cross_round_interaction(&final_response, "g")
            .is_ok());
    }

    #[test]
    fn repeated_challenge_registration_is_idempotent() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_label(b"repeated-registration");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        transcript.add_response("z", Value::int(5), &["e"]).unwrap();

        transcript.record_challenge_multiplication("z", "e").unwrap();
        transcript.record_challenge_multiplication("z", "e").unwrap();

        assert_eq!(transcript.challenges_mul["z"].len(), 1);
        assert!(transcript.challenges_mul["z"].contains("e"));
    }

    #[test]
    fn same_round_objects_do_not_require_challenge_registration() {
        let mut transcript = TranscriptInspector::with_label(b"same-round-objects");
        transcript.add("left", "prover", ObjectCategory::Constant, Value::int(2)).unwrap();
        transcript.add("right", "prover", ObjectCategory::Constant, Value::int(3)).unwrap();

        assert!(transcript.check_cross_round_interaction("left", "right").is_ok());
    }

    #[test]
    fn invalid_challenge_batch_does_not_mutate_transcript() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_label(b"invalid-challenge-batch");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        let before = transcript.transcript_bytes().to_vec();

        assert!(transcript
            .record_challenges::<Sha3_256>(&["e", "e"], &["g", "m"], &BigInt::from(97))
            .is_err());
        assert_eq!(transcript.transcript_bytes(), before);
        assert!(!transcript.elements.contains_key("e"));
        assert_eq!(transcript.round, 0);
    }

    #[test]
    fn empty_challenge_batch_and_invalid_order_are_rejected() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_label(b"challenge-batch-boundaries");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();

        assert!(matches!(
            transcript.record_challenges::<Sha3_256>(&[], &["g", "m"], &BigInt::from(97)),
            Err(TranscriptError::TypeError(_))
        ));
        assert!(matches!(
            transcript.record_challenges::<Sha3_256>(&["e"], &["g", "m"], &BigInt::from(0)),
            Err(TranscriptError::TypeError(_))
        ));
        assert_eq!(transcript.round, 0);
    }

    #[test]
    fn challenge_cannot_be_registered_for_an_element_from_an_earlier_round() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_label(b"future-challenge");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();

        assert!(matches!(
            transcript.record_challenge_multiplication("m", "e"),
            Err(TranscriptError::UnsafeCrossRoundInteraction(_, _))
        ));
        assert!(transcript.challenges_mul["m"].is_empty());
    }

    #[test]
    fn challenge_registration_rejects_unknown_target() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_label(b"unknown-target");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();

        assert!(matches!(
            transcript.record_challenge_multiplication("missing", "e"),
            Err(TranscriptError::TypeError(_))
        ));
    }
}
