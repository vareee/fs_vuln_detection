use std::collections::{HashMap, HashSet};
use std::borrow::Borrow;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};
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
    EmptyElementLabel,
    DuplicateElementLabel(String),
    UnknownElement(String),
    DifferentTranscripts,
    InspectionUnavailable,
    InspectionStatePoisoned,
    TypeError(String),
    /// a heuristic finding, not a proof that the protocol is insecure
    SuspiciousCrossRoundInteraction(String, String),
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
            TranscriptError::EmptyElementLabel => write!(f, "Transcript element label cannot be empty!"),
            TranscriptError::DuplicateElementLabel(label) => write!(f, "Transcript element label '{}' is already registered!", label),
            TranscriptError::UnknownElement(label) => write!(f, "Transcript element '{}' is not registered!", label),
            TranscriptError::TypeError(msg) => write!(f, "{}", msg),
            TranscriptError::DifferentTranscripts => write!(f, "Objects from different transcripts cannot interact!"),
            TranscriptError::InspectionUnavailable => write!(f, "The value's inspection context is unavailable!"),
            TranscriptError::InspectionStatePoisoned => write!(f, "The inspection state cannot be accessed after a panic!"),
            TranscriptError::SuspiciousCrossRoundInteraction(o1, o2) => write!(f,
                "Suspicious interaction between '{}' and '{}': no sufficiently late challenge in the observed computation", o1, o2),
        }
    }
}

impl std::error::Error for TranscriptError {}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionMode {
    /// enforce validation and stop on suspicious round-provenance patterns
    Full,
    /// preserve transcript operations without applying security checks
    Disabled,
}


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

impl From<BigInt> for Value {
    fn from(value: BigInt) -> Self {
        Self::Integer(value)
    }
}

impl From<ProjectivePoint> for Value {
    fn from(value: ProjectivePoint) -> Self {
        Self::Point(value)
    }
}

impl From<Vec<Value>> for Value {
    fn from(value: Vec<Value>) -> Self {
        Self::List(value)
    }
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

pub fn serialize_point(p: &ProjectivePoint) -> Option<([u8; 32], [u8; 32])> {
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

/// arithmetic checks transcript identity and a heuristic round-provenance policy before recording its origin
///
/// cloning preserves origin identity, while arithmetic creates a new origin without changing transcript bytes
/// full inspection requires the owning inspector to remain alive
///
/// external code cannot construct a tagged value or replace its value or transcript id
///
/// ```compile_fail
/// use fs_vuln_detection::{TaggedValue, Value};
///
/// let forged = TaggedValue {
///     value: Value::int(1),
///     transcript_id: todo!()
/// };
/// ```
///
/// arithmetic accepts only values already tagged by a transcript
///
/// ```compile_fail
/// use fs_vuln_detection::{TranscriptInspector, Value};
/// use num_bigint::BigInt;
///
/// let mut transcript = TranscriptInspector::new(b"compile-time-check");
/// let tagged = transcript.add_constant("tagged", Value::int(1)).unwrap();
/// let result = tagged + BigInt::from(2);
/// ```
#[derive(Debug, Clone)]
pub struct TaggedValue {
    /// algebraic value owned by this wrapper
    pub(crate) value: Value,
    /// id of the only transcript in which this value may participate
    pub(crate) transcript_id: Uuid,
    /// opaque identity in the inspector's journal, absent when inspection is disabled
    origin_id: Option<usize>,
    /// non-owning connection to inspection metadata, never to another arithmetic wrapper
    inspection: Weak<Mutex<Vec<ValueOrigin>>>,
}

impl TaggedValue {
    pub(crate) fn new(value: Value, transcript_id: Uuid) -> Self {
        Self { 
            value, 
            transcript_id,
            origin_id: None,
            inspection: Weak::new()
        } 
    }

    /// return the wrapped value
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// consume the wrapper and return its value, discarding its tracked origin
    pub fn into_value(self) -> Value {
        self.value
    }

    fn ensure_same_transcript_id(&self, other: &TaggedValue) -> Result<(), TranscriptError> {
        if self.transcript_id != other.transcript_id {
            Err(TranscriptError::DifferentTranscripts)
        } else { Ok(()) }
    }

    fn record_origin(
        &self,
        value: Value,
        operation: OriginOperation
    ) -> Result<TaggedValue, TranscriptError> {
        let inspection = self.inspection.upgrade()
            .ok_or(TranscriptError::InspectionUnavailable)?;
        let mut origins = inspection.lock()
            .map_err(|_| TranscriptError::InspectionStatePoisoned)?;
        let origin = ValueOrigin::from_operation(operation, &origins)?;
        let origin_id = origins.len();
        origins.push(origin);
        Ok(Self {
            value,
            transcript_id: self.transcript_id,
            origin_id: Some(origin_id),
            inspection: self.inspection.clone()
        })
    }

    fn record_binary(
        &self,
        other: &TaggedValue,
        value: Value,
        operation: fn(usize, usize) -> OriginOperation
    ) -> Result<TaggedValue, TranscriptError> {
        self.ensure_same_transcript_id(other)?;
        if self.transcript_id.is_nil() {
            return Ok(Self::new(value, self.transcript_id));
        }
        let left = self.origin_id.ok_or(TranscriptError::InspectionUnavailable)?;
        let right = other.origin_id.ok_or(TranscriptError::InspectionUnavailable)?;
        if !Weak::ptr_eq(&self.inspection, &other.inspection) {
            return Err(TranscriptError::DifferentTranscripts);
        }
        self.record_origin(value, operation(left, right))
    }

    fn record_unary(
        &self,
        value: Value,
        operation: impl FnOnce(usize) -> OriginOperation
    ) -> Result<TaggedValue, TranscriptError> {
        if self.transcript_id.is_nil() {
            return Ok(Self::new(value, self.transcript_id));
        }
        let operand = self.origin_id.ok_or(TranscriptError::InspectionUnavailable)?;
        self.record_origin(value, operation(operand))
    }

    fn checked_add(&self, other: &TaggedValue) -> Result<TaggedValue, TranscriptError> {
        self.ensure_same_transcript_id(other)?;
        let value = match (&self.value, &other.value) {
            (Value::Integer(a), Value::Integer(b)) => Value::Integer(a + b),
            (Value::Point(a), Value::Point(b)) => Value::Point(*a + *b),
            _ => return Err(TranscriptError::TypeError(
                "Unsupported types for addition!".to_string(),
            )),
        };
        self.record_binary(other, value, OriginOperation::Add)
    }

    fn checked_sub(&self, other: &TaggedValue) -> Result<TaggedValue, TranscriptError> {
        self.ensure_same_transcript_id(other)?;
        let value = match (&self.value, &other.value) {
            (Value::Integer(a), Value::Integer(b)) => Value::Integer(a - b),
            (Value::Point(a), Value::Point(b)) => Value::Point(*a - *b),
            _ => return Err(TranscriptError::TypeError(
                "Unsupported types for substraction!".into(),
            )),
        };
        self.record_binary(other, value, OriginOperation::Sub)
    }

    fn checked_mul(&self, other: &TaggedValue) -> Result<TaggedValue, TranscriptError> {
        self.ensure_same_transcript_id(other)?;
        let value = match (&self.value, &other.value) {
            (Value::Integer(a), Value::Integer(b)) => Value::Integer(a * b),
            (Value::Integer(a), Value::Point(point)) => {
                Value::Point(*point * bigint_to_scalar(a))
            }
            (Value::Point(point), Value::Integer(a)) => {
                Value::Point(*point * bigint_to_scalar(a))
            }
            _ => return Err(TranscriptError::TypeError(
                "Unsupported types for multiplication!".to_string(),
            )),
        };
        self.record_binary(other, value, OriginOperation::Mul)
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

    pub fn as_list(&self) -> Option<&[Value]> {
        if let Value::List(v) = &self.value { 
            Some(v) 
        } else { None }
    }

    pub fn get(&self, index: usize) -> Result<TaggedValue, TranscriptError> {
        match &self.value {
            Value::List(values) => {
                let value = values.get(index).cloned().ok_or_else(|| TranscriptError::TypeError(
                    format!("List index {} is out of bounds", index)
                ))?;
                self.record_unary(value, |list| OriginOperation::ListElement { list, index })
            }
            _ => Err(TranscriptError::TypeError(
                "TaggedValue is not a list".to_string()
            ))
        }
    }

    pub fn modulo(&self, modulus: &TaggedValue) -> Result<TaggedValue, TranscriptError> {
        self.ensure_same_transcript_id(modulus)?;
        match (&self.value, &modulus.value) {
            (Value::Integer(a), Value::Integer(m)) => {
                if m.is_zero() {
                    return Err(TranscriptError::TypeError("Modulo by zero".to_string()));
                }
                self.record_binary(modulus, Value::Integer(a.mod_floor(m)), OriginOperation::Modulo)
            }
            _ => Err(TranscriptError::TypeError("Modulo only on Integer".to_string())),
        }
    }

    pub fn modpow(&self, exp: &BigInt, modulus: &BigInt) -> Result<TaggedValue, TranscriptError> {
        if modulus.is_zero() {
            return Err(TranscriptError::TypeError("Modulo by zero".to_string()));
        }
        match &self.value {
            Value::Integer(b) => {
                let val = if exp.is_negative() {
                    let inv = mod_inverse(b, modulus).ok_or_else(||
                        TranscriptError::TypeError("No modular inverse!".to_string()))?;
                    inv.modpow(&(-exp), modulus)
                } else {
                    b.modpow(exp, modulus)
                };
                self.record_unary(Value::Integer(val), OriginOperation::ModPowUntrackedParameters)
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

impl<Rhs: Borrow<TaggedValue>> std::ops::Add<Rhs> for TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;

    fn add(self, other: Rhs) -> Self::Output {
        self.checked_add(other.borrow())
    }
}

impl<Rhs: Borrow<TaggedValue>> std::ops::Add<Rhs> for &TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;

    fn add(self, other: Rhs) -> Self::Output {
        self.checked_add(other.borrow())
    }
}

impl<Rhs: Borrow<TaggedValue>> std::ops::Sub<Rhs> for TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;

    fn sub(self, other: Rhs) -> Self::Output {
        self.checked_sub(other.borrow())
    }
}

impl<Rhs: Borrow<TaggedValue>> std::ops::Sub<Rhs> for &TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;

    fn sub(self, other: Rhs) -> Self::Output {
        self.checked_sub(other.borrow())
    }
}

impl<Rhs: Borrow<TaggedValue>> std::ops::Mul<Rhs> for TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;

    fn mul(self, other: Rhs) -> Self::Output {
        self.checked_mul(other.borrow())
    }
}

impl<Rhs: Borrow<TaggedValue>> std::ops::Mul<Rhs> for &TaggedValue {
    type Output = Result<TaggedValue, TranscriptError>;

    fn mul(self, other: Rhs) -> Self::Output {
        self.checked_mul(other.borrow())
    }
}


// operation kinds and inspection summaries belong to one inspector-owned journal
#[derive(Debug, Clone, PartialEq, Eq)]
enum OriginOperation {
    Registered { element_index: usize, source: Option<usize> },
    Add(usize, usize),
    Sub(usize, usize),
    Mul(usize, usize),
    Modulo(usize, usize),
    ListElement { list: usize, index: usize },
    ModPowUntrackedParameters(usize),
    #[cfg(test)]
    TestInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValueOrigin {
    operation: OriginOperation,
    // none or a nonempty sorted unique set, shared when an operation does not change it
    submitted_rounds: Option<Arc<[usize]>>,
    // only the latest challenge round is needed by the heuristic
    latest_challenge: Option<usize>,
    label: Option<String>,
}

impl ValueOrigin {
    fn check_interaction(
        left: &Self,
        right: &Self,
        left_id: usize,
        right_id: usize
    ) -> Result<(), TranscriptError> {
        let (Some(left_rounds), Some(right_rounds)) = (&left.submitted_rounds, &right.submitted_rounds) else {
            return Ok(());
        };
        if Arc::ptr_eq(left_rounds, right_rounds) || left_rounds == right_rounds {
            return Ok(());
        }
        let latest_submission = left_rounds.last().copied().max(right_rounds.last().copied())
            .ok_or(TranscriptError::InspectionUnavailable)?;
        let latest_challenge = left.latest_challenge.max(right.latest_challenge);
        // generated challenges hash the cumulative transcript through their own round
        // this is a syntactic heuristic, not a verifier equation or a security proof
        if latest_challenge.is_some_and(|round| round >= latest_submission) {
            return Ok(());
        }
        let describe = |origin: &Self, id| origin.label.clone()
            .unwrap_or_else(|| format!("operation #{id}"));
        Err(TranscriptError::SuspiciousCrossRoundInteraction(
            describe(left, left_id), describe(right, right_id)
        ))
    }

    fn merge_submitted_rounds(
        left: &Option<Arc<[usize]>>,
        right: &Option<Arc<[usize]>>
    ) -> Option<Arc<[usize]>> {
        let (Some(left), Some(right)) = (left, right) else {
            return left.as_ref().or(right.as_ref()).cloned();
        };
        if Arc::ptr_eq(left, right) || left == right {
            return Some(Arc::clone(left));
        }
        let (smaller, larger) = if left.len() < right.len() { (left, right) } else { (right, left) };
        if smaller.len() < larger.len() {
            let mut index = 0;
            for round in larger.iter() {
                if smaller.get(index) == Some(round) {
                    index += 1;
                    if index == smaller.len() {
                        return Some(Arc::clone(larger));
                    }
                }
            }
        }

        let mut merged = Vec::with_capacity(left.len() + right.len());
        let (mut left_index, mut right_index) = (0, 0);
        while left_index < left.len() && right_index < right.len() {
            match left[left_index].cmp(&right[right_index]) {
                std::cmp::Ordering::Less => {
                    merged.push(left[left_index]);
                    left_index += 1;
                }
                std::cmp::Ordering::Greater => {
                    merged.push(right[right_index]);
                    right_index += 1;
                }
                std::cmp::Ordering::Equal => {
                    merged.push(left[left_index]);
                    left_index += 1;
                    right_index += 1;
                }
            }
        }
        merged.extend_from_slice(&left[left_index..]);
        merged.extend_from_slice(&right[right_index..]);
        Some(merged.into())
    }

    fn from_operation(
        operation: OriginOperation,
        origins: &[Self]
    ) -> Result<Self, TranscriptError> {
        let get = |id| origins.get(id).ok_or(TranscriptError::InspectionUnavailable);
        let (submitted_rounds, latest_challenge) = match operation {
            OriginOperation::Add(left, right) | OriginOperation::Sub(left, right)
                | OriginOperation::Mul(left, right) | OriginOperation::Modulo(left, right) =>
            {
                let left_origin = get(left)?;
                let right_origin = get(right)?;
                Self::check_interaction(left_origin, right_origin, left, right)?;
                (Self::merge_submitted_rounds(&left_origin.submitted_rounds, &right_origin.submitted_rounds),
                    left_origin.latest_challenge.max(right_origin.latest_challenge))
            }
            OriginOperation::ListElement { list, .. } => {
                let list = get(list)?;
                (list.submitted_rounds.clone(), list.latest_challenge)
            }
            OriginOperation::ModPowUntrackedParameters(base) => {
                // only the base is observed, raw exponent and modulus stay outside the journal
                let base = get(base)?;
                (base.submitted_rounds.clone(), base.latest_challenge)
            }
            // registration metadata must be assigned by the inspector, never by arithmetic
            OriginOperation::Registered { .. } => return Err(TranscriptError::InspectionUnavailable),
            #[cfg(test)]
            OriginOperation::TestInput => (None, None)
        };
        Ok(Self { operation, submitted_rounds, latest_challenge, label: None })
    }
}

#[derive(Debug, Clone)]
struct TranscriptElement {
    #[allow(dead_code)] subject: String,
    category: ObjectCategory,
    #[allow(dead_code)] index: usize,
    #[allow(dead_code)] round: usize,
    #[allow(dead_code)]
    tagged_value: TaggedValue,
}

/// transcript state and inspection metadata
///
/// local responses use tracked computations, received responses enter through add_received_response
///
/// ```compile_fail
/// use fs_vuln_detection::{TranscriptInspector, Value};
///
/// let mut transcript = TranscriptInspector::new(b"compile-time-check");
/// transcript.add_response("response", Value::int(1)).unwrap();
/// ```
pub struct TranscriptInspector {
    transcript_id: Uuid,
    mode: InspectionMode,
    elements: HashMap<String, TranscriptElement>,
    challenges: HashMap<String, HashSet<usize>>,
    index: usize,
    round: usize,
    constant_num: usize,
    transcript: Vec<u8>,
    inspection: Arc<Mutex<Vec<ValueOrigin>>>,
}


fn serialize_value_into(buf: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Integer(b) => {
            buf.push(0x01);
            buf.extend_from_slice(&bigint_to_be32(b));
        }
        Value::Point(p) => {
            buf.push(0x02);
            match serialize_point(p) {
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
    /// create a transcript with full inspection enabled
    pub fn new(protocol_label: &[u8]) -> Self {
        Self::with_mode(protocol_label, InspectionMode::Full)
    }

    /// create a transcript with an explicit inspection mode
    pub fn with_mode(protocol_label: &[u8], mode: InspectionMode) -> Self {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&(protocol_label.len() as u32).to_be_bytes());
        transcript.extend_from_slice(protocol_label);
        Self {
            transcript_id: if mode == InspectionMode::Full {
                Uuid::new_v4()
            } else {
                Uuid::nil()
            },
            mode,
            elements: HashMap::new(),
            challenges: HashMap::new(),
            index: 0,
            round: 0,
            constant_num: 0,
            transcript,
            inspection: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// return the configured inspection mode
    pub fn mode(&self) -> InspectionMode {
        self.mode
    }

    fn inspections_enabled(&self) -> bool {
        self.mode == InspectionMode::Full
    }

    #[cfg(test)]
    fn get_transcript_id(&self) -> Uuid {
        self.transcript_id 
    }

    #[cfg(test)]
    fn tag(&self, value: Value) -> TaggedValue {
        if !self.inspections_enabled() {
            return TaggedValue::new(value, self.transcript_id);
        }
        let mut origins = self.inspection.lock().unwrap();
        let origin_id = origins.len();
        origins.push(ValueOrigin::from_operation(OriginOperation::TestInput, &[]).unwrap());
        TaggedValue {
            value,
            transcript_id: self.transcript_id,
            origin_id: Some(origin_id),
            inspection: Arc::downgrade(&self.inspection)
        }
    }

    /// return the cryptographic transcript without inspection metadata
    pub fn transcript_bytes(&self) -> &[u8] {
        &self.transcript 
    }

    // add object to transcript (who did it, its category (pubkey, challenge, ...), its number in transcript and round number)
    fn add(
        &mut self,
        name: &str,
        subject: &str,
        category: ObjectCategory,
        value: Value
    ) -> Result<TaggedValue, TranscriptError> {
        let inspection = Arc::clone(&self.inspection);
        let mut origins = if self.inspections_enabled() {
            Some(inspection.lock().map_err(|_| TranscriptError::InspectionStatePoisoned)?)
        } else {
            None
        };
        self.add_with_origin(name, subject, category, value, None, origins.as_deref_mut())
    }

    fn add_with_origin(
        &mut self,
        name: &str,
        subject: &str,
        category: ObjectCategory,
        value: Value,
        source: Option<usize>,
        origins: Option<&mut Vec<ValueOrigin>>
    ) -> Result<TaggedValue, TranscriptError> {
        if name.is_empty() {
            return Err(TranscriptError::EmptyElementLabel);
        }
        if self.elements.contains_key(name) {
            return Err(TranscriptError::DuplicateElementLabel(name.to_string()));
        }
        if self.inspections_enabled()
            && category == ObjectCategory::Pubkey
            && !self.challenges.is_empty()
        {
            return Err(TranscriptError::ElementAddedAfterChallenge(
                name.to_string(), category.to_string()));
        }

        let mut tagged = TaggedValue::new(value, self.transcript_id);
        if let Some(origins) = origins {
            let mut origin = match source {
                Some(source) => origins.get(source)
                    .ok_or(TranscriptError::InspectionUnavailable)?.clone(),
                None => ValueOrigin {
                    operation: OriginOperation::Registered { element_index: self.index, source: None },
                    submitted_rounds: if matches!(category,
                        ObjectCategory::Constant | ObjectCategory::Generator | ObjectCategory::Challenge
                    ) {
                        None
                    } else {
                        Some(Arc::from([self.round]))
                    },
                    latest_challenge: (category == ObjectCategory::Challenge).then_some(self.round),
                    label: None
                }
            };
            origin.operation = OriginOperation::Registered { element_index: self.index, source };
            origin.label = Some(name.to_string());
            tagged.origin_id = Some(origins.len());
            tagged.inspection = Arc::downgrade(&self.inspection);
            origins.push(origin);
        }
        if category != ObjectCategory::Constant {
            serialize_value_into(&mut self.transcript, &tagged.value);
        }
        self.elements.insert(name.to_string(), TranscriptElement {
            subject: subject.to_string(),
            category, index: self.index, round: self.round,
            tagged_value: tagged.clone(),
        });
        if category == ObjectCategory::Constant { self.constant_num += 1; }
        self.index += 1;
        Ok(tagged)
    }

    /// add a fixed protocol generator, neutral to rounds but included in transcript bytes
    /// the caller must validate protocol parameters rather than relabel fresh prover inputs
    pub fn add_generator<V: Into<Value>>(
        &mut self,
        label: &str,
        value: V
    ) -> Result<TaggedValue, TranscriptError> {
        self.add_generator_for(label, "verifier", value)
    }

    /// add a fixed protocol generator associated with an explicitly named participant
    pub fn add_generator_for<V: Into<Value>>(
        &mut self,
        label: &str,
        subject: &str,
        value: V
    ) -> Result<TaggedValue, TranscriptError> {
        self.add(label, subject, ObjectCategory::Generator, value.into())
    }

    /// add a public key owned by the default prover
    pub fn add_public_key<V: Into<Value>>(
        &mut self,
        label: &str,
        value: V
    ) -> Result<TaggedValue, TranscriptError> {
        self.add_public_key_for(label, "prover", value)
    }

    /// add a public key owned by an explicitly named participant
    pub fn add_public_key_for<V: Into<Value>>(
        &mut self,
        label: &str,
        subject: &str,
        value: V
    ) -> Result<TaggedValue, TranscriptError> {
        self.add(label, subject, ObjectCategory::Pubkey, value.into())
    }

    /// add a commitment owned by the default prover
    pub fn add_commitment<V: Into<Value>>(&mut self, label: &str, value: V) -> Result<TaggedValue, TranscriptError> {
        self.add_commitment_for(label, "prover", value)
    }

    /// add a commitment owned by an explicitly named participant
    pub fn add_commitment_for<V: Into<Value>>(
        &mut self,
        label: &str,
        subject: &str,
        value: V
    ) -> Result<TaggedValue, TranscriptError> {
        self.add(label, subject, ObjectCategory::Commitment, value.into())
    }

    /// add a message owned by the default prover
    pub fn add_message<V: Into<Value>>(&mut self, label: &str, value: V) -> Result<TaggedValue, TranscriptError> {
        self.add_message_for(label, "prover", value)
    }

    /// add a message owned by an explicitly named participant
    pub fn add_message_for<V: Into<Value>>(
        &mut self,
        label: &str,
        subject: &str,
        value: V
    ) -> Result<TaggedValue, TranscriptError> {
        self.add(label, subject, ObjectCategory::Message, value.into())
    }

    /// add a constant owned by the default prover
    pub fn add_constant<V: Into<Value>>(&mut self, label: &str, value: V) -> Result<TaggedValue, TranscriptError> {
        self.add_constant_for(label, "prover", value)
    }

    /// add a constant owned by an explicitly named participant
    pub fn add_constant_for<V: Into<Value>>(
        &mut self,
        label: &str,
        subject: &str,
        value: V
    ) -> Result<TaggedValue, TranscriptError> {
        self.add(label, subject, ObjectCategory::Constant, value.into())
    }

    fn validate_challenge_batch(
        &self,
        challenge_names: &[&str],
        used_names: &[&str],
        order: &BigInt
    ) -> Result<HashSet<usize>, TranscriptError> {
        if challenge_names.is_empty() {
            return Err(TranscriptError::TypeError(
                "At least one challenge name is required".to_string(),
            ));
        }
        if order <= &BigInt::one() {
            return Err(TranscriptError::TypeError(
                "Order must be greater than one".to_string(),
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
            if challenge_name.is_empty() {
                return Err(TranscriptError::EmptyElementLabel);
            }
            if self.elements.contains_key(*challenge_name) {
                return Err(TranscriptError::DuplicateElementLabel(
                    challenge_name.to_string()
                ));
            }
        }

        if !self.inspections_enabled() {
            return Ok(HashSet::new());
        }
        let used_set: HashSet<&str> = used_names.iter().copied().collect();
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
        let referenced_msgs_count = used_set.iter().filter(|name| {
            self.elements.get(**name).is_some_and(|e| matches!(
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
        for name in &used_set {
            match self.elements.get(*name) {
                Some(info) => {
                    if info.category == ObjectCategory::Message { pt_found = true; }
                    else if info.category == ObjectCategory::Generator { gen_found = true; }
                }
                None => return Err(TranscriptError::UnknownElementInChallenge( // error if an argument was not declared in transcript
                    challenge_names[0].to_string(), (*name).to_string())),
            }
        }
        if self.challenges.is_empty() {
            if !pt_found { return Err(TranscriptError::PlaintextNotInFirstChallenge); } // error if plaintext was not hashed in the first challenge
            if !gen_found { return Err(TranscriptError::GeneratorNotInFirstChallenge); } // error if generator (of a group or an ellicptic curve) was not hashed in the first challenge
        }

        Ok(used_set
            .into_iter()
            .map(|name| self.elements[name].index)
            .collect())
    }

    /// create several scalar Fiat-Shamir challenges in one logical protocol round
    ///
    /// every hash output is reduced modulo the supplied `order`
    ///
    /// the `order` applies only to this call, is shared by the batch and is not stored in the transcript
    pub fn record_challenges<H: FSHash>(
        &mut self,
        challenge_names: &[&str],
        used_names: &[&str],
        order: &BigInt
    ) -> Result<Vec<TaggedValue>, TranscriptError> {
        let used_set = self.validate_challenge_batch(
            challenge_names,
            used_names,
            order
        )?;
        // prepare the complete batch before committing either bytes or origin records
        // hashing runs outside the metadata lock because FSHash is supplied by the caller
        let mut next_transcript = self.transcript.clone();
        let mut values = Vec::with_capacity(challenge_names.len());
        for _ in challenge_names {
            let digest = H::hash(&next_transcript);
            let value = Value::Integer(
                BigInt::from_bytes_be(num_bigint::Sign::Plus, &digest).mod_floor(order)
            );
            serialize_value_into(&mut next_transcript, &value);
            values.push(value);
        }
        let inspection = Arc::clone(&self.inspection);
        let mut origins = if self.inspections_enabled() {
            Some(inspection.lock().map_err(|_| TranscriptError::InspectionStatePoisoned)?)
        } else {
            None
        };
        let mut tagged_challenges = Vec::with_capacity(challenge_names.len());
        for (challenge_name, value) in challenge_names.iter().zip(values) {
            let tagged = self.add_with_origin(
                challenge_name, "verifier",
                ObjectCategory::Challenge, value, None, origins.as_deref_mut()
            )?;
            if self.inspections_enabled() {
                self.challenges.insert(challenge_name.to_string(), used_set.clone());
            }
            tagged_challenges.push(tagged);
        }
        self.round += 1;
        Ok(tagged_challenges)
    }

    /// create one scalar challenge and finish the current logical round
    ///
    /// the hash output is reduced modulo `order` for this challenge only
    pub fn record_challenge<H: FSHash>(&mut self, challenge_name: &str, used_names: &[&str], order: &BigInt) -> Result<TaggedValue, TranscriptError> {
        self.record_challenges::<H>(&[challenge_name], used_names, order)?
            .into_iter()
            .next()
            .ok_or_else(|| TranscriptError::TypeError(
                "Challenge generation returned no value".to_string(),
            ))
    }

    /// preserve the computed origin when registering a prover response
    /// arithmetic has already applied the heuristic to every recorded interaction
    /// registration preserves the source provenance and does not invent new dependencies
    pub fn add_response(
        &mut self,
        name: &str,
        response: TaggedValue
    ) -> Result<TaggedValue, TranscriptError> {
        if self.inspections_enabled() && response.transcript_id != self.transcript_id {
            return Err(TranscriptError::DifferentTranscripts);
        }
        if self.elements.contains_key(name) {
            return Err(TranscriptError::TypeError(format!(
                "Transcript element '{}' already exists",
                name,
            )));
        }
        if !self.inspections_enabled() {
            return self.add(name, "prover", ObjectCategory::Response, response.value);
        }
        let source = response.origin_id.ok_or(TranscriptError::InspectionUnavailable)?;
        if !Weak::ptr_eq(&response.inspection, &Arc::downgrade(&self.inspection)) {
            return Err(TranscriptError::DifferentTranscripts);
        }
        let inspection = Arc::clone(&self.inspection);
        let mut origins = inspection.lock()
            .map_err(|_| TranscriptError::InspectionStatePoisoned)?;
        if source >= origins.len() {
            return Err(TranscriptError::InspectionUnavailable);
        }
        self.add_with_origin(
            name, "prover", ObjectCategory::Response, response.value,
            Some(source), Some(&mut origins)
        )
    }

    /// register an externally received response without assuming how the prover computed it
    /// the protocol verifier must still validate the response using its verification equations
    pub fn add_received_response<V: Into<Value>>(
        &mut self,
        label: &str,
        value: V
    ) -> Result<TaggedValue, TranscriptError> {
        self.add(label, "prover", ObjectCategory::Response, value.into())
    }

    /// optionally inspect registered operands without performing an arithmetic operation
    /// arithmetic applies the same round-provenance heuristic automatically
    pub fn check_cross_round_interaction(
        &self, object1: &str, object2: &str
    ) -> Result<(), TranscriptError> {
        if !self.inspections_enabled() {
            return Ok(());
        }
        let info1 = self.elements.get(object1).ok_or_else(||
            TranscriptError::UnknownElement(object1.into()))?;
        let info2 = self.elements.get(object2).ok_or_else(||
            TranscriptError::UnknownElement(object2.into()))?;
        let origins = self.inspection.lock()
            .map_err(|_| TranscriptError::InspectionStatePoisoned)?;
        let origin1 = info1.tagged_value.origin_id.ok_or(TranscriptError::InspectionUnavailable)?;
        let origin2 = info2.tagged_value.origin_id.ok_or(TranscriptError::InspectionUnavailable)?;
        let left = origins.get(origin1).ok_or(TranscriptError::InspectionUnavailable)?;
        let right = origins.get(origin2).ok_or(TranscriptError::InspectionUnavailable)?;
        ValueOrigin::check_interaction(left, right, origin1, origin2)
    }

}

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

    fn test_transcript(label: &[u8]) -> TranscriptInspector {
        TranscriptInspector::new(label)
    }

    fn expected_challenge<H: FSHash>(
        transcript: &TranscriptInspector,
        order: &BigInt
    ) -> BigInt {
        BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            &H::hash(transcript.transcript_bytes())
        )
        .mod_floor(order)
    }

    #[test]
    fn new_enables_full_inspection() {
        let transcript = test_transcript(b"full-by-default");

        assert_eq!(transcript.mode(), InspectionMode::Full);
    }

    #[test]
    fn inspection_mode_does_not_change_valid_challenges() {
        use sha3::Sha3_256;

        let order = secp256k1_order();
        let mut full = TranscriptInspector::with_mode(
            b"same-protocol",
            InspectionMode::Full
        );
        let mut disabled = TranscriptInspector::with_mode(
            b"same-protocol",
            InspectionMode::Disabled
        );

        for transcript in [&mut full, &mut disabled] {
            transcript.add_generator("g", Value::int(2)).unwrap();
            transcript.add_message("m", Value::int(3)).unwrap();
        }

        let full_challenge = full
            .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
            .unwrap();
        let disabled_challenge = disabled
            .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
            .unwrap();

        assert_eq!(full_challenge.as_bigint(), disabled_challenge.as_bigint());
        assert_eq!(full.transcript_bytes(), disabled.transcript_bytes());
    }

    #[test]
    fn disabled_mode_skips_security_checks() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_mode(
            b"disabled-checks",
            InspectionMode::Disabled
        );

        transcript
            .record_challenge::<Sha3_256>(
                "e",
                &["unknown"],
                &BigInt::from(97)
            )
            .unwrap();
        transcript.add_public_key("late-key", Value::int(3)).unwrap();
        assert!(transcript
            .check_cross_round_interaction("unknown", "unknown")
            .is_ok());
    }

    #[test]
    fn disabled_mode_does_not_retain_inspection_graphs() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_mode(
            b"disabled-metadata",
            InspectionMode::Disabled
        );
        transcript.add_generator("g", Value::int(2)).unwrap();
        transcript.add_message("m", Value::int(3)).unwrap();
        let challenge = transcript
            .record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97))
            .unwrap();
        transcript
            .add_response("r", challenge)
            .unwrap();

        assert!(transcript.challenges.is_empty());
        assert!(transcript.inspection.lock().unwrap().is_empty());
        assert_eq!(transcript.elements.len(), 4);
    }

    #[test]
    fn disabled_mode_accepts_foreign_response() {
        let mut source = test_transcript(b"source");
        let response = source.add_constant("response", Value::int(5)).unwrap();
        let mut transcript = TranscriptInspector::with_mode(
            b"disabled-response",
            InspectionMode::Disabled
        );

        assert!(transcript
            .add_response("response", response)
            .is_ok());
    }

    #[test]
    fn disabled_transcripts_allow_cross_transcript_arithmetic() {
        let mut first = TranscriptInspector::with_mode(
            b"first",
            InspectionMode::Disabled
        );
        let mut second = TranscriptInspector::with_mode(
            b"second",
            InspectionMode::Disabled
        );
        let left = first.add_constant("left", Value::int(2)).unwrap();
        let right = second.add_constant("right", Value::int(3)).unwrap();

        assert_eq!((left + right).unwrap().as_bigint(), Some(&BigInt::from(5)));
    }

    #[test]
    fn disabled_mode_keeps_structural_validation() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_mode(
            b"structural-validation",
            InspectionMode::Disabled
        );
        transcript.add_message("m", Value::int(3)).unwrap();

        assert!(matches!(
            transcript.add_message("m", Value::int(4)),
            Err(TranscriptError::DuplicateElementLabel(_))
        ));
        assert!(matches!(
            transcript.record_challenge::<Sha3_256>(
                "e",
                &["m"],
                &BigInt::one()
            ),
            Err(TranscriptError::TypeError(_))
        ));
    }

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
        let insp = test_transcript(b"tagged-arithmetic");
        let g = insp.tag(Value::Point(ProjectivePoint::GENERATOR));
        let s = insp.tag(Value::Integer(BigInt::from(3)));
        let prod = (&s * &g).unwrap();
        let prod2 = (&g * &s).unwrap();
        assert_eq!(prod.value, prod2.value);
    }

    #[test]
    fn tagged_list_access_is_checked() {
        let transcript = test_transcript(b"tagged-list-access");
        let list = transcript.tag(Value::List(vec![Value::int(3)]));
        let integer = transcript.tag(Value::int(3));

        assert_eq!(list.get(0).unwrap().as_bigint(), Some(&BigInt::from(3)));
        assert!(list.get(1).is_err());
        assert!(integer.get(0).is_err());
    }

    #[test]
    fn test_cross_transcript_error() {
        let a = test_transcript(b"transcript-a");
        let b = test_transcript(b"transcript-b");
        let v1 = a.tag(Value::Integer(BigInt::from(1)));
        let v2 = b.tag(Value::Integer(BigInt::from(2)));
        assert_ne!(a.get_transcript_id(), b.get_transcript_id());
        assert!((&v1 + &v2).is_err());
    }

    #[test]
    fn test_specialized_add_methods() {
        let mut transcript = test_transcript(b"specialized-add-methods");

        transcript.add_generator("g", Value::int(2)).unwrap();
        transcript.add_public_key("pk", Value::int(3)).unwrap();
        transcript.add_commitment("commitment", Value::int(5)).unwrap();
        transcript.add_message_for("message", "prover2", Value::int(7)).unwrap();
        transcript.add_constant("constant", Value::int(11)).unwrap();

        assert_eq!(transcript.elements["g"].category, ObjectCategory::Generator);
        assert_eq!(transcript.elements["pk"].category, ObjectCategory::Pubkey);
        assert_eq!(transcript.elements["commitment"].category, ObjectCategory::Commitment);
        assert_eq!(transcript.elements["message"].category, ObjectCategory::Message);
        assert_eq!(transcript.elements["constant"].category, ObjectCategory::Constant);
        assert_eq!(transcript.elements["g"].subject, "verifier");
        assert_eq!(transcript.elements["pk"].subject, "prover");
        assert_eq!(transcript.elements["message"].subject, "prover2");
    }

    #[test]
    fn repeated_element_label_is_rejected_without_mutation() {
        let mut transcript = test_transcript(b"repeated-label");
        transcript.add_commitment("element", Value::int(2)).unwrap();
        let transcript_before = transcript.transcript_bytes().to_vec();
        let elements_before = transcript.elements.len();

        let result = transcript.add_message("element", Value::int(3));

        assert!(matches!(
            result,
            Err(TranscriptError::DuplicateElementLabel(label)) if label == "element"
        ));
        assert_eq!(transcript.transcript_bytes(), transcript_before);
        assert_eq!(transcript.elements.len(), elements_before);
    }

    #[test]
    fn empty_element_label_is_rejected_without_mutation() {
        let mut transcript = test_transcript(b"empty-label");
        let transcript_before = transcript.transcript_bytes().to_vec();

        let result = transcript.add_message("", Value::int(3));

        assert!(matches!(result, Err(TranscriptError::EmptyElementLabel)));
        assert_eq!(transcript.transcript_bytes(), transcript_before);
        assert!(transcript.elements.is_empty());
    }

    #[test]
    fn test_cross_round_challenge() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"cross-round-safe");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        let later = transcript.add_message("later", Value::int(5)).unwrap();
        let next = transcript.record_challenge::<Sha3_256>("next", &["g", "m", "later"], &BigInt::from(97)).unwrap();
        let response = ((challenge + next).unwrap() + message).unwrap();
        transcript.add_response("z", response).unwrap();

        assert!(transcript.check_cross_round_interaction("z", "later").is_ok());
        assert!((transcript.elements["z"].tagged_value.clone() + later).is_ok());
    }

    #[test]
    fn test_cross_round_without_challenge() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"cross-round-unsafe");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        transcript.add("z", "prover", ObjectCategory::Response, Value::int(5)).unwrap();

        assert!(matches!(
            transcript.check_cross_round_interaction("z", "m"),
            Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _))
        ));
    }

    #[test]
    fn test_raw_challenge_copy() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"cross-round-invalid-challenge");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        let copy = transcript.add_constant("copy", challenge.into_value()).unwrap();
        let unprotected = (copy * message).unwrap();
        let later = transcript.add_message("later", Value::int(5)).unwrap();

        assert!(matches!(
            unprotected + later,
            Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _))
        ));
    }

    #[test]
    fn owned_tagged_values_support_natural_rust_operators() {
        let transcript = test_transcript(b"owned-operators");
        let e = transcript.tag(Value::int(7));
        let message = transcript.tag(Value::int(3));
        let public_key = transcript.tag(Value::int(29));

        let e_msg = (e * message).unwrap();
        let response = (public_key - e_msg).unwrap();

        assert_eq!(response.as_bigint(), Some(&BigInt::from(8)));
    }

    #[test]
    fn test_response_preserves_dependencies() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"response-api");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        let response = (challenge * message).unwrap();
        let response = transcript.add_response("z", response).unwrap();

        let origins = transcript.inspection.lock().unwrap();
        let origin = &origins[response.origin_id.unwrap()];
        assert_eq!(origin.submitted_rounds.as_deref(), Some([0].as_slice()));
        assert_eq!(origin.latest_challenge, Some(0));
    }

    #[test]
    fn add_response_does_not_mutate_transcript_when_origin_is_invalid() {
        let mut transcript = test_transcript(b"response-api-invalid");
        let before = transcript.transcript_bytes().to_vec();

        let mut response = transcript.tag(Value::int(5));
        let origins = transcript.inspection.lock().unwrap().clone();
        response.origin_id = Some(usize::MAX);
        assert!(matches!(transcript.add_response("z", response), Err(TranscriptError::InspectionUnavailable)));
        assert_eq!(*transcript.inspection.lock().unwrap(), origins);
        assert_eq!(transcript.transcript_bytes(), before);
        assert!(!transcript.elements.contains_key("z"));
    }

    #[test]
    fn add_response_rejects_name_of_an_existing_non_response() {
        let mut transcript = test_transcript(b"response-name-collision");
        transcript.add("z", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        let before = transcript.transcript_bytes().to_vec();

        let response = transcript.tag(Value::int(5));
        assert!(matches!(
            transcript.add_response("z", response),
            Err(TranscriptError::TypeError(_))
        ));
        assert_eq!(transcript.transcript_bytes(), before);
    }

    #[test]
    fn add_response_rejects_repeated_response_name() {
        let mut transcript = test_transcript(b"repeated-response-name");
        let response = transcript.tag(Value::int(5));
        transcript.add_response("z", response).unwrap();
        let before = transcript.transcript_bytes().to_vec();

        let response = transcript.tag(Value::int(7));
        assert!(matches!(
            transcript.add_response("z", response),
            Err(TranscriptError::TypeError(_))
        ));
        assert_eq!(transcript.transcript_bytes(), before);
        assert_eq!(transcript.elements["z"].tagged_value.as_bigint(), Some(&BigInt::from(5)));
    }

    #[test]
    fn several_challenges_can_belong_to_one_round() {
        use sha3::Sha3_256;

        let order = secp256k1_order();
        let mut transcript = test_transcript(b"same-round-challenges");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();

        let challenges = transcript
            .record_challenges::<Sha3_256>(&["y", "z"], &["g", "m"], &order)
            .unwrap();

        assert_eq!(challenges.len(), 2);
        assert_eq!(transcript.elements["y"].round, 0);
        assert_eq!(transcript.elements["z"].round, 0);
        assert_eq!(transcript.round, 1);
        for challenge in &challenges {
            let value = challenge.as_bigint().unwrap();
            assert!(value >= &BigInt::zero());
            assert!(value < &order);
        }
        assert_ne!(challenges[0].as_bigint(), challenges[1].as_bigint());

        let scalar = transcript.add_constant("scalar", Value::int(5)).unwrap();
        for (index, challenge) in challenges.into_iter().enumerate() {
            let label = format!("response_{index}");
            let response = (challenge * &scalar).unwrap();
            transcript.add_response(&label, response).unwrap();
            assert!(transcript.check_cross_round_interaction(&label, "g").is_ok());
        }
    }

    #[test]
    fn challenge_inputs_are_stored_as_element_indices() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"indexed-challenge-inputs");
        transcript.add_generator("g", Value::int(2)).unwrap();
        transcript.add_message("m", Value::int(3)).unwrap();
        let expected = HashSet::from([
            transcript.elements["g"].index,
            transcript.elements["m"].index
        ]);

        transcript
            .record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97))
            .unwrap();

        assert_eq!(transcript.challenges["e"], expected);
    }

    #[test]
    fn test_multi_round_interaction() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"non-adjacent-rounds");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let mut challenges = transcript
            .record_challenges::<Sha3_256>(&["y", "z"], &["g", "m"], &BigInt::from(97))
            .unwrap().into_iter();
        let y = challenges.next().unwrap();
        let z = challenges.next().unwrap();
        let r1 = (y * &message).unwrap();
        transcript.add_response("r1", r1).unwrap();
        let x = transcript
            .record_challenge::<Sha3_256>("x", &["g", "m", "r1"], &BigInt::from(97))
            .unwrap();
        assert!((&x * &message).is_ok());
        let scalar = transcript.add_constant("scalar", Value::int(7)).unwrap();
        let r2 = (x * scalar).unwrap();
        let r2 = transcript.add_response("r2", r2).unwrap();

        assert!(transcript.check_cross_round_interaction("r2", "r1").is_ok());
        assert!(transcript.check_cross_round_interaction("r2", "g").is_ok());

        let mixed = (r2 + (z * message).unwrap()).unwrap();
        transcript.add_response("mixed", mixed).unwrap();
        assert!(transcript.check_cross_round_interaction("mixed", "g").is_ok());
        assert!(transcript.check_cross_round_interaction("mixed", "r1").is_ok());
        transcript.add_message("later", Value::int(13)).unwrap();
        assert!(matches!(
            transcript.check_cross_round_interaction("mixed", "later"),
            Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _))
        ));
    }

    #[test]
    fn cross_round_check_supports_an_arbitrary_number_of_rounds() {
        use sha3::Sha3_256;

        const ROUND_COUNT: usize = 32;
        let mut transcript = test_transcript(b"arbitrary-round-count");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let mut prover_elements = vec!["g".to_string(), "m".to_string()];
        let mut chain = message.clone();

        for round in 0..ROUND_COUNT {
            let message_name = format!("m_{round}");
            let current = transcript.add_message(&message_name, Value::int(3)).unwrap();
            prover_elements.push(message_name);
            if round > 0 {
                assert!(matches!(
                    &chain + &current,
                    Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _))
                ));
            }
            let challenge_name = format!("e_{round}");
            let response_name = format!("r_{round}");
            let used_names: Vec<&str> = prover_elements.iter().map(String::as_str).collect();
            let challenge = transcript
                .record_challenge::<Sha3_256>(
                    &challenge_name,
                    &used_names,
                    &BigInt::from(97)
                )
                .unwrap();
            let covered = (challenge * chain).unwrap();
            chain = (covered + current).unwrap();
            let response = transcript
                .add_response(
                    &response_name,
                    chain.clone()
                )
                .unwrap();
            assert_eq!(response.value(), chain.value());

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
        assert!(transcript.check_cross_round_interaction(&final_response, "m").is_ok());
        transcript.add_response("mixed", chain).unwrap();
        assert!(transcript
            .check_cross_round_interaction("mixed", "g")
            .is_ok());
        let origins = transcript.inspection.lock().unwrap();
        let mixed = &origins[transcript.elements["mixed"].tagged_value.origin_id.unwrap()];
        assert_eq!(mixed.submitted_rounds.as_deref(), Some((0..ROUND_COUNT).collect::<Vec<_>>().as_slice()));
        assert_eq!(mixed.latest_challenge, Some(ROUND_COUNT - 1));
    }

    #[test]
    fn repeated_response_registration_preserves_dependencies() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"repeated-registration");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        let response = (challenge * message).unwrap();
        transcript.add_response("z", response.clone()).unwrap();
        transcript.add_response("z_copy", response).unwrap();

        let before = transcript.inspection.lock().unwrap().clone();
        for _ in 0..2 {
            assert!(transcript.check_cross_round_interaction("z", "g").is_ok());
            assert!(transcript.check_cross_round_interaction("z_copy", "g").is_ok());
        }
        assert_eq!(*transcript.inspection.lock().unwrap(), before);
    }

    #[test]
    fn same_round_objects_do_not_require_challenge_registration() {
        let mut transcript = test_transcript(b"same-round-objects");
        transcript.add_message("left", Value::int(2)).unwrap();
        transcript.add_message("right", Value::int(3)).unwrap();

        assert!(transcript.check_cross_round_interaction("left", "right").is_ok());
    }

    #[test]
    fn invalid_challenge_batch_does_not_mutate_transcript() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"invalid-challenge-batch");
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
    fn challenge_validation_reports_input_errors() {
        use sha3::Sha3_256;

        let order = BigInt::from(97);
        let mut transcript = test_transcript(b"challenge-input-errors");
        transcript.add_generator("g", Value::int(2)).unwrap();
        transcript.add_message("m", Value::int(3)).unwrap();
        transcript.add_public_key("key", Value::int(5)).unwrap();
        let before = transcript.transcript_bytes().to_vec();

        assert!(matches!(
            transcript.record_challenge::<Sha3_256>("incomplete", &["g", "m"], &order),
            Err(TranscriptError::NotEveryProverMessagesIncluded)
        ));
        assert!(matches!(
            transcript.record_challenge::<Sha3_256>(
                "unknown",
                &["g", "m", "key", "missing"],
                &order
            ),
            Err(TranscriptError::UnknownElementInChallenge(_, _))
        ));
        assert!(matches!(
            transcript.record_challenge::<Sha3_256>(
                "duplicate",
                &["g", "m", "key", "m"],
                &order
            ),
            Err(TranscriptError::DuplicateElementsInChallenge)
        ));
        assert_eq!(transcript.transcript_bytes(), before);

        let mut without_message = test_transcript(b"without-message");
        without_message.add_generator("g", Value::int(2)).unwrap();
        assert!(matches!(
            without_message.record_challenge::<Sha3_256>("e", &["g"], &order),
            Err(TranscriptError::PlaintextNotInFirstChallenge)
        ));

        let mut without_generator = test_transcript(b"without-generator");
        without_generator.add_message("m", Value::int(3)).unwrap();
        assert!(matches!(
            without_generator.record_challenge::<Sha3_256>("e", &["m"], &order),
            Err(TranscriptError::GeneratorNotInFirstChallenge)
        ));
    }

    #[test]
    fn empty_challenge_batch_and_invalid_order_are_rejected() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"challenge-batch-boundaries");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();

        assert!(matches!(
            transcript.record_challenges::<Sha3_256>(&[], &["g", "m"], &BigInt::from(97)),
            Err(TranscriptError::TypeError(_))
        ));
        assert!(matches!(
            transcript.record_challenges::<Sha3_256>(&["e"], &["g", "m"], &BigInt::one()),
            Err(TranscriptError::TypeError(_))
        ));
        assert!(matches!(
            transcript.record_challenges::<Sha3_256>(&["e"], &["g", "m"], &BigInt::zero()),
            Err(TranscriptError::TypeError(_))
        ));
        assert!(matches!(
            transcript.record_challenges::<Sha3_256>(&["e"], &["g", "m"], &BigInt::from(-1)),
            Err(TranscriptError::TypeError(_))
        ));
        assert_eq!(transcript.round, 0);
    }

    #[test]
    fn challenges_can_use_different_orders_in_one_transcript() {
        use sha3::Sha3_256;

        let first_order = BigInt::from(13);
        let second_order = BigInt::from(17);
        let mut transcript = test_transcript(b"different-challenge-orders");
        transcript.add_generator("g", Value::int(2)).unwrap();
        transcript.add_message("m", Value::int(3)).unwrap();

        let expected_first = expected_challenge::<Sha3_256>(
            &transcript,
            &first_order
        );
        let first = transcript
            .record_challenge::<Sha3_256>("e1", &["g", "m"], &first_order)
            .unwrap();

        let expected_second = expected_challenge::<Sha3_256>(
            &transcript,
            &second_order
        );
        let second = transcript
            .record_challenge::<Sha3_256>("e2", &["g", "m"], &second_order)
            .unwrap();

        assert_eq!(first.as_bigint(), Some(&expected_first));
        assert_eq!(second.as_bigint(), Some(&expected_second));
    }

    #[test]
    fn identical_transcripts_generate_identical_challenges() {
        use sha3::Sha3_256;

        let order = secp256k1_order();
        let mut first = test_transcript(b"deterministic-challenge");
        let mut second = test_transcript(b"deterministic-challenge");

        for transcript in [&mut first, &mut second] {
            transcript.add_generator("g", Value::int(2)).unwrap();
            transcript.add_message("m", Value::int(3)).unwrap();
        }

        let first_challenge = first
            .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
            .unwrap();
        let second_challenge = second
            .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
            .unwrap();

        assert_eq!(first_challenge.as_bigint(), second_challenge.as_bigint());
        assert_eq!(first.transcript_bytes(), second.transcript_bytes());
    }

    #[test]
    fn empty_protocol_label_is_allowed() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"");
        transcript.add_generator("g", Value::int(2)).unwrap();
        transcript.add_message("m", Value::int(3)).unwrap();

        assert!(transcript
            .record_challenge::<Sha3_256>(
                "e",
                &["g", "m"],
                &BigInt::from(97)
            )
            .is_ok());
    }

    #[test]
    fn challenge_labels_do_not_change_challenge_values() {
        use sha3::Sha3_256;

        let order = secp256k1_order();
        let mut first = test_transcript(b"challenge-labels");
        let mut second = test_transcript(b"challenge-labels");

        for transcript in [&mut first, &mut second] {
            transcript.add_generator("g", Value::int(2)).unwrap();
            transcript.add_message("m", Value::int(3)).unwrap();
        }

        let first_challenge = first
            .record_challenge::<Sha3_256>("e1", &["g", "m"], &order)
            .unwrap();
        let second_challenge = second
            .record_challenge::<Sha3_256>("e2", &["g", "m"], &order)
            .unwrap();

        assert_eq!(first_challenge.as_bigint(), second_challenge.as_bigint());
        assert_eq!(first.transcript_bytes(), second.transcript_bytes());
    }

    #[test]
    fn element_labels_do_not_change_challenge_values() {
        use sha3::Sha3_256;

        let order = secp256k1_order();
        let mut first = test_transcript(b"same-protocol");
        let mut second = test_transcript(b"same-protocol");

        first.add_generator("g", Value::int(2)).unwrap();
        first.add_message("m", Value::int(3)).unwrap();
        second.add_generator("generator", Value::int(2)).unwrap();
        second.add_message("message", Value::int(3)).unwrap();

        let first_challenge = first
            .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
            .unwrap();
        let second_challenge = second
            .record_challenge::<Sha3_256>(
                "challenge",
                &["generator", "message"],
                &order
            )
            .unwrap();

        assert_eq!(first_challenge.as_bigint(), second_challenge.as_bigint());
        assert_eq!(first.transcript_bytes(), second.transcript_bytes());
    }

    #[test]
    fn private_constants_do_not_change_challenge_values() {
        use sha3::Sha3_256;

        let order = secp256k1_order();
        let mut prover = test_transcript(b"same-protocol");
        let mut verifier = test_transcript(b"same-protocol");

        prover.add_constant("secret", Value::int(11)).unwrap();
        for transcript in [&mut prover, &mut verifier] {
            transcript.add_generator("g", Value::int(2)).unwrap();
            transcript.add_message("m", Value::int(3)).unwrap();
        }

        let prover_challenge = prover
            .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
            .unwrap();
        let verifier_challenge = verifier
            .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
            .unwrap();

        assert_eq!(prover_challenge.as_bigint(), verifier_challenge.as_bigint());
        assert_eq!(prover.transcript_bytes(), verifier.transcript_bytes());
    }

    #[test]
    fn protocol_labels_separate_challenge_values() {
        use sha3::Sha3_256;

        let order = secp256k1_order();
        let mut first = test_transcript(b"protocol/v1/group");
        let mut second = test_transcript(b"protocol/v2/group");

        for transcript in [&mut first, &mut second] {
            transcript.add_generator("g", Value::int(2)).unwrap();
            transcript.add_message("m", Value::int(3)).unwrap();
        }

        let first_challenge = first
            .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
            .unwrap();
        let second_challenge = second
            .record_challenge::<Sha3_256>("e", &["g", "m"], &order)
            .unwrap();

        assert_ne!(first_challenge.as_bigint(), second_challenge.as_bigint());
        assert_ne!(first.transcript_bytes(), second.transcript_bytes());
    }

    #[test]
    fn later_multiplication_does_not_change_an_earlier_origin() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"future-challenge");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        transcript.add_response("unprotected", message.clone()).unwrap();
        let response = (challenge * message).unwrap();
        transcript.add_response("protected", response).unwrap();
        transcript.add_message("later", Value::int(11)).unwrap();

        assert!(matches!(
            transcript.check_cross_round_interaction("unprotected", "later"),
            Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _))
        ));
        assert!(transcript.check_cross_round_interaction("protected", "m").is_ok());
    }

    #[test]
    fn cross_round_check_rejects_unknown_target() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"unknown-target");
        transcript.add("g", "verifier", ObjectCategory::Generator, Value::int(2)).unwrap();
        transcript.add("m", "verifier", ObjectCategory::Message, Value::int(3)).unwrap();
        transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();

        assert!(matches!(
            transcript.check_cross_round_interaction("missing", "e"),
            Err(TranscriptError::UnknownElement(label)) if label == "missing"
        ));
    }

    #[test]
    fn test_origin_identity() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"origin-identity");
        transcript.add_generator("g", Value::int(2)).unwrap();
        let first = transcript.add_message("first", Value::int(5)).unwrap();
        let count = transcript.inspection.lock().unwrap().len();
        let copy = first.clone();
        assert_eq!(copy.origin_id, first.origin_id);
        assert!(Weak::ptr_eq(&copy.inspection, &first.inspection));
        assert_eq!(transcript.inspection.lock().unwrap().len(), count);

        transcript.record_challenge::<Sha3_256>("e", &["g", "first"], &BigInt::from(97)).unwrap();
        let second = transcript.add_message("second", Value::int(5)).unwrap();
        assert_eq!(first.value(), second.value());
        assert_ne!(first.origin_id, second.origin_id);
        assert_eq!(transcript.elements["first"].round, 0);
        assert_eq!(transcript.elements["second"].round, 1);
        let origins = transcript.inspection.lock().unwrap();
        assert_eq!(origins[first.origin_id.unwrap()].operation, OriginOperation::Registered {
            element_index: transcript.elements["first"].index,
            source: None
        });
        assert_eq!(origins[second.origin_id.unwrap()].operation, OriginOperation::Registered {
            element_index: transcript.elements["second"].index,
            source: None
        });
    }

    #[test]
    fn test_arithmetic_origins() {
        let mut transcript = test_transcript(b"arithmetic-origins");
        let left = transcript.add_message("left", Value::int(5)).unwrap();
        let right = transcript.add_message("right", Value::int(3)).unwrap();
        let before = transcript.transcript_bytes().to_vec();
        let index = transcript.index;
        let round = transcript.round;
        let product = (&left * &right).unwrap();
        let difference = (&left - &product).unwrap();
        let sum = (&difference + &right).unwrap();

        let origins = transcript.inspection.lock().unwrap();
        assert_eq!(origins.len(), 5);
        assert_eq!(origins[product.origin_id.unwrap()].operation, OriginOperation::Mul(
            left.origin_id.unwrap(), right.origin_id.unwrap()
        ));
        assert_eq!(origins[difference.origin_id.unwrap()].operation, OriginOperation::Sub(
            left.origin_id.unwrap(), product.origin_id.unwrap()
        ));
        assert_eq!(origins[sum.origin_id.unwrap()].operation, OriginOperation::Add(
            difference.origin_id.unwrap(), right.origin_id.unwrap()
        ));
        assert_eq!(sum.as_bigint(), Some(&BigInt::from(-7)));
        assert_eq!(transcript.transcript_bytes(), before);
        assert_eq!(transcript.index, index);
        assert_eq!(transcript.round, round);
        assert_eq!(transcript.elements.len(), 2);
    }

    #[test]
    fn test_owned_operation_origins() {
        let mut transcript = test_transcript(b"owned-origins");
        let left = transcript.add_constant("left", Value::int(5)).unwrap();
        let right = transcript.add_constant("right", Value::int(3)).unwrap();
        let results = [
            (&left * &right).unwrap(),
            (left.clone() * &right).unwrap(),
            (&left * right.clone()).unwrap(),
            (left.clone() * right.clone()).unwrap()
        ];
        let origins = transcript.inspection.lock().unwrap();
        let mut ids = HashSet::new();
        for result in results {
            assert_eq!(result.as_bigint(), Some(&BigInt::from(15)));
            assert!(ids.insert(result.origin_id));
            assert_eq!(origins[result.origin_id.unwrap()].operation, OriginOperation::Mul(
                left.origin_id.unwrap(), right.origin_id.unwrap()
            ));
        }
    }

    #[test]
    fn test_response_origin() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"response-origin");
        transcript.add_generator("g", Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>(
            "e", &["g", "m"], &BigInt::from(97)
        ).unwrap();
        let result = (challenge * message).unwrap();
        let original = result.clone();
        let first = transcript.add_response("first", result).unwrap();
        let first_copy = first.clone();
        transcript.record_challenge::<Sha3_256>(
            "e2", &["g", "m", "first"], &BigInt::from(97)
        ).unwrap();
        let second = transcript.add_response("second", first_copy).unwrap();

        assert_ne!(first.origin_id, original.origin_id);
        assert_ne!(second.origin_id, first.origin_id);
        assert_eq!(transcript.elements["first"].round, 1);
        assert_eq!(transcript.elements["second"].round, 2);
        let origins = transcript.inspection.lock().unwrap();
        assert!(matches!(origins[original.origin_id.unwrap()].operation, OriginOperation::Mul(_, _)));
        assert_eq!(origins[first.origin_id.unwrap()].operation, OriginOperation::Registered {
            element_index: transcript.elements["first"].index,
            source: original.origin_id
        });
        assert_eq!(origins[second.origin_id.unwrap()].operation, OriginOperation::Registered {
            element_index: transcript.elements["second"].index,
            source: first.origin_id
        });
    }

    #[test]
    fn test_auxiliary_origins() {
        let mut transcript = test_transcript(b"auxiliary-origins");
        let list = transcript.add_constant("list", vec![Value::int(5)]).unwrap();
        let modulus = transcript.add_constant("modulus", Value::int(3)).unwrap();
        let item = list.get(0).unwrap();
        let reduced = item.modulo(&modulus).unwrap();
        let power = item.modpow(&BigInt::from(2), &BigInt::from(7)).unwrap();
        let combined = (&power + &reduced).unwrap();

        assert_eq!(reduced.as_bigint(), Some(&BigInt::from(2)));
        assert_eq!(power.as_bigint(), Some(&BigInt::from(4)));
        let origins = transcript.inspection.lock().unwrap();
        assert_eq!(origins[item.origin_id.unwrap()].operation, OriginOperation::ListElement {
            list: list.origin_id.unwrap(), index: 0
        });
        assert_eq!(origins[reduced.origin_id.unwrap()].operation, OriginOperation::Modulo(
            item.origin_id.unwrap(), modulus.origin_id.unwrap()
        ));
        assert_eq!(origins[power.origin_id.unwrap()].operation, OriginOperation::ModPowUntrackedParameters(
            item.origin_id.unwrap()
        ));
        assert_eq!(origins[combined.origin_id.unwrap()].operation, OriginOperation::Add(
            power.origin_id.unwrap(), reduced.origin_id.unwrap()
        ));
    }

    #[test]
    fn test_origin_errors() {
        let mut transcript = test_transcript(b"origin-errors");
        let scalar = transcript.add_constant("scalar", Value::int(3)).unwrap();
        let zero = transcript.add_constant("zero", Value::int(0)).unwrap();
        let point = transcript.add_constant("point", ProjectivePoint::GENERATOR).unwrap();
        let list = transcript.add_constant("list", vec![Value::int(5)]).unwrap();
        let mut foreign = test_transcript(b"foreign-origin");
        let other = foreign.add_constant("scalar", Value::int(3)).unwrap();
        let before = transcript.inspection.lock().unwrap().clone();
        let bytes = transcript.transcript_bytes().to_vec();

        assert!(matches!(&scalar + &point, Err(TranscriptError::TypeError(_))));
        assert!(matches!(&scalar * &other, Err(TranscriptError::DifferentTranscripts)));
        assert!(list.get(1).is_err());
        assert!(scalar.get(0).is_err());
        assert!(scalar.modulo(&zero).is_err());
        assert!(scalar.modpow(&BigInt::from(2), &BigInt::zero()).is_err());
        assert!(zero.modpow(&BigInt::from(-1), &BigInt::from(7)).is_err());
        assert!(transcript.add_response("", scalar.clone()).is_err());
        let mut invalid = scalar.clone();
        invalid.origin_id = None;
        assert!(transcript.add_response("response", invalid).is_err());
        assert!(transcript.add_response("scalar", scalar.clone()).is_err());
        assert!(transcript.add_response("response", other).is_err());
        assert_eq!(*transcript.inspection.lock().unwrap(), before);
        assert_eq!(transcript.transcript_bytes(), bytes);
        assert_eq!(transcript.index, 4);
    }

    #[test]
    fn test_cross_round_arithmetic_atomicity() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"arithmetic-atomicity");
        transcript.add_generator("g", Value::int(2)).unwrap();
        let earlier = transcript.add_message("earlier", Value::int(3)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>(
            "e", &["g", "earlier"], &BigInt::from(97)
        ).unwrap();
        let later = transcript.add_message("later", Value::int(5)).unwrap();
        let origins = transcript.inspection.lock().unwrap().clone();
        let bytes = transcript.transcript_bytes().to_vec();
        let index = transcript.index;
        let round = transcript.round;
        let elements = transcript.elements.len();

        for result in [
            &earlier + &later,
            &later - &earlier,
            &earlier * &later,
            earlier.modulo(&later),
            later.modulo(&earlier)
        ] {
            assert!(matches!(result, Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _))));
            assert_eq!(*transcript.inspection.lock().unwrap(), origins);
            assert_eq!(transcript.transcript_bytes(), bytes);
            assert_eq!(transcript.index, index);
            assert_eq!(transcript.round, round);
            assert_eq!(transcript.elements.len(), elements);
        }

        let product = (challenge * earlier).unwrap();
        assert_eq!(product.origin_id, Some(origins.len()));
        assert_eq!(transcript.inspection.lock().unwrap().len(), origins.len() + 1);
        assert!(matches!(&product + &later, Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _))));
        let next = transcript.record_challenge::<Sha3_256>(
            "next", &["g", "earlier", "later"], &BigInt::from(97)
        ).unwrap();
        assert!(((next * product).unwrap() + later).is_ok());
    }

    #[test]
    fn test_origin_rounds() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"origin-rounds");
        let generator = transcript.add_generator("g", Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let constant = transcript.add_constant("factor", Value::int(2)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>(
            "e", &["g", "m"], &BigInt::from(97)
        ).unwrap();
        let sum = (&message + &message).unwrap();
        let sum = (sum + &message).unwrap();
        let product = (&challenge * &sum).unwrap();
        transcript.record_challenge::<Sha3_256>(
            "next", &["g", "m"], &BigInt::from(97)
        ).unwrap();
        let alias = transcript.add_response("alias", product.clone()).unwrap();
        let challenge_alias = transcript.add_response("challenge_alias", challenge.clone()).unwrap();

        let origins = transcript.inspection.lock().unwrap();
        let origin = |value: &TaggedValue| &origins[value.origin_id.unwrap()];
        for value in [&constant, &generator] {
            assert!(origin(value).submitted_rounds.is_none());
            assert!(origin(value).latest_challenge.is_none());
        }
        for value in [&message, &sum] {
            assert_eq!(origin(value).submitted_rounds.as_deref(), Some([0].as_slice()));
            assert!(origin(value).latest_challenge.is_none());
        }
        for value in [&challenge, &challenge_alias] {
            assert!(origin(value).submitted_rounds.is_none());
            assert_eq!(origin(value).latest_challenge, Some(0));
        }
        for value in [&product, &alias] {
            assert_eq!(origin(value).submitted_rounds.as_deref(), Some([0].as_slice()));
            assert_eq!(origin(value).latest_challenge, Some(0));
        }
        assert_eq!(transcript.elements["alias"].round, 2);
        assert_eq!(transcript.elements["challenge_alias"].round, 2);
    }

    #[test]
    fn test_round_sets() {
        let rounds = |bits: usize| (0..4).filter(|round| bits & (1 << round) != 0).collect::<HashSet<_>>();
        let compact = |rounds: &HashSet<usize>| {
            if rounds.is_empty() {
                None
            } else {
                let mut sorted: Vec<_> = rounds.iter().copied().collect();
                sorted.sort_unstable();
                Some(Arc::<[usize]>::from(sorted))
            }
        };
        // exercise synthetic summaries, including equal maxima but different submitted sets
        for left_bits in 0..16 {
            for right_bits in 0..16 {
                for challenge_bits in 0..16 {
                    let submitted_left = rounds(left_bits);
                    let submitted_right = rounds(right_bits);
                    let challenges = rounds(challenge_bits);
                    let submitted: HashSet<_> = submitted_left.union(&submitted_right).copied().collect();
                    let accepted = submitted_left.is_empty() || submitted_right.is_empty()
                        || submitted_left == submitted_right
                        || challenges.iter().any(|challenge| submitted.iter().all(|round| round <= challenge));
                    let origins = [
                        ValueOrigin {
                            operation: OriginOperation::TestInput,
                            submitted_rounds: compact(&submitted_left),
                            latest_challenge: rounds(challenge_bits & 0b0101).into_iter().max(),
                            label: None
                        },
                        ValueOrigin {
                            operation: OriginOperation::TestInput,
                            submitted_rounds: compact(&submitted_right),
                            latest_challenge: rounds(challenge_bits & 0b1010).into_iter().max(),
                            label: None
                        }
                    ];
                    for operation in [OriginOperation::Add(0, 1), OriginOperation::Sub(0, 1),
                        OriginOperation::Mul(0, 1), OriginOperation::Modulo(0, 1)] {
                        match ValueOrigin::from_operation(operation, &origins) {
                            Ok(origin) => {
                                assert!(accepted);
                                assert_eq!(origin.submitted_rounds, compact(&submitted));
                                assert_eq!(origin.latest_challenge, challenges.iter().copied().max());
                            }
                            Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _)) => assert!(!accepted),
                            Err(error) => panic!("unexpected error: {error}")
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_submitted_rounds_union() {
        let values = [0, 2, 63, usize::MAX];
        let rounds = |bits: usize| {
            let values: Vec<_> = values.iter().enumerate()
                .filter_map(|(index, round)| (bits & (1 << index) != 0).then_some(*round)).collect();
            if values.is_empty() { None } else { Some(Arc::<[usize]>::from(values)) }
        };
        for left_bits in 0..16 {
            for right_bits in 0..16 {
                let left = rounds(left_bits);
                let right = rounds(right_bits);
                let expected = rounds(left_bits | right_bits);
                for (first, second) in [(&left, &right), (&right, &left)] {
                    let merged = ValueOrigin::merge_submitted_rounds(first, second);
                    assert_eq!(merged, expected);
                    if let Some(merged) = merged {
                        let reusable = [first, second].into_iter().flatten()
                            .filter(|source| source.as_ref() == merged.as_ref()).collect::<Vec<_>>();
                        if !reusable.is_empty() {
                            assert!(reusable.iter().any(|source| Arc::ptr_eq(source, &merged)));
                        }
                        assert!(merged.windows(2).all(|pair| pair[0] < pair[1]));
                    }
                }
                assert_eq!(left, rounds(left_bits));
                assert_eq!(right, rounds(right_bits));
            }
        }
    }

    #[test]
    fn test_sparse_round_interaction() {
        let left = ValueOrigin {
            operation: OriginOperation::TestInput,
            submitted_rounds: Some(Arc::from([0, usize::MAX])),
            latest_challenge: Some(usize::MAX - 1),
            label: None
        };
        let mut right = ValueOrigin {
            operation: OriginOperation::TestInput,
            submitted_rounds: Some(Arc::from([2, usize::MAX])),
            latest_challenge: None,
            label: None
        };
        assert!(matches!(ValueOrigin::check_interaction(&left, &right, 0, 1),
            Err(TranscriptError::SuspiciousCrossRoundInteraction(_, _))));
        right.latest_challenge = Some(usize::MAX);
        assert!(ValueOrigin::check_interaction(&left, &right, 0, 1).is_ok());
        assert!(ValueOrigin::check_interaction(&right, &left, 1, 0).is_ok());
    }

    #[test]
    fn test_shared_origin_storage() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"shared-origin-storage");
        let generator = transcript.add_generator("g", Value::int(2)).unwrap();
        let list = transcript.add_message("m", vec![Value::int(5)]).unwrap();
        let modulus = transcript.add_constant("modulus", Value::int(3)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>("e", &["g", "m"], &BigInt::from(97)).unwrap();
        let item = list.get(0).unwrap();
        let product = (&challenge * &item).unwrap();
        let reduced = product.modulo(&modulus).unwrap();
        let power = product.modpow(&BigInt::from(2), &BigInt::from(7)).unwrap();
        let alias = transcript.add_response("response", product.clone()).unwrap();
        let neutral = (&generator + &modulus).unwrap();
        let origins = transcript.inspection.lock().unwrap();
        let input_rounds = origins[list.origin_id.unwrap()].submitted_rounds.as_ref().unwrap();
        for value in [&item, &product, &reduced, &power, &alias] {
            let origin = &origins[value.origin_id.unwrap()];
            assert!(Arc::ptr_eq(input_rounds, origin.submitted_rounds.as_ref().unwrap()));
        }
        for value in [&generator, &modulus, &challenge, &neutral] {
            assert!(origins[value.origin_id.unwrap()].submitted_rounds.is_none());
        }
        assert_eq!(origins[alias.origin_id.unwrap()].latest_challenge, Some(0));
        assert_eq!(origins[list.origin_id.unwrap()].latest_challenge, None);
    }

    #[test]
    fn test_origin_layout() {
        // the compact record must stay smaller than the two former set headers alone
        assert!(std::mem::size_of::<ValueOrigin>() < 2 * std::mem::size_of::<HashSet<usize>>());
        println!("value_origin_bytes={}", std::mem::size_of::<ValueOrigin>());
    }

    #[test]
    fn test_failed_response_preserves_computation() {
        let mut transcript = test_transcript(b"failed-response-origin");
        let scalar = transcript.add_constant("scalar", Value::int(3)).unwrap();
        let result = (&scalar * &scalar).unwrap();
        let before = transcript.inspection.lock().unwrap().clone();
        assert!(transcript.add_response("", result.clone()).is_err());
        assert_eq!(*transcript.inspection.lock().unwrap(), before);
        let registered = transcript.add_response("valid", result.clone()).unwrap();
        let origins = transcript.inspection.lock().unwrap();
        assert_eq!(origins.len(), before.len() + 1);
        assert_eq!(origins[registered.origin_id.unwrap()].operation, OriginOperation::Registered {
            element_index: transcript.elements["valid"].index,
            source: result.origin_id
        });
    }

    #[test]
    fn test_disabled_origins() {
        use sha3::Sha3_256;

        let mut transcript = TranscriptInspector::with_mode(b"disabled-origins", InspectionMode::Disabled);
        let list = transcript.add_constant("list", vec![Value::int(5)]).unwrap();
        let scalar = transcript.add_constant("scalar", Value::int(3)).unwrap();
        let item = list.get(0).unwrap();
        let product = (&item * &scalar).unwrap();
        let sum = (product + &scalar).unwrap();
        let difference = (sum - &item).unwrap();
        let reduced = difference.modulo(&scalar).unwrap();
        let power = reduced.modpow(&BigInt::from(2), &BigInt::from(7)).unwrap();
        let response = transcript.add_response("response", power).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>("e", &[], &BigInt::from(97)).unwrap();

        for value in [&list, &scalar, &item, &reduced, &response, &challenge] {
            assert_eq!(value.origin_id, None);
            assert!(value.inspection.upgrade().is_none());
        }
        assert!(transcript.inspection.lock().unwrap().is_empty());
    }

    #[test]
    fn test_cross_round_check_reads_origins() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"checked-origin");
        transcript.add_generator("g", Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>(
            "e", &["g", "m"], &BigInt::from(97)
        ).unwrap();
        let result = (challenge * message).unwrap();
        transcript.add_response("r", result).unwrap();
        let before = transcript.inspection.lock().unwrap().clone();
        let bytes = transcript.transcript_bytes().to_vec();
        assert!(transcript.check_cross_round_interaction("r", "m").is_ok());
        assert!(transcript.check_cross_round_interaction("m", "r").is_ok());
        assert_eq!(*transcript.inspection.lock().unwrap(), before);
        assert_eq!(transcript.transcript_bytes(), bytes);
    }

    #[test]
    fn test_cross_round_poisoned_inspection() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"poisoned-cross-round");
        transcript.add_generator("g", Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let challenge = transcript.record_challenge::<Sha3_256>(
            "e", &["g", "m"], &BigInt::from(97)
        ).unwrap();
        transcript.add_response("r", (challenge * message).unwrap()).unwrap();
        let before = transcript.inspection.lock().unwrap().clone();
        let bytes = transcript.transcript_bytes().to_vec();
        let inspection = Arc::clone(&transcript.inspection);
        assert!(std::panic::catch_unwind(|| {
            let _guard = inspection.lock().unwrap();
            panic!("test poisoned cross-round state");
        }).is_err());

        assert!(matches!(
            transcript.check_cross_round_interaction("r", "m"),
            Err(TranscriptError::InspectionStatePoisoned)
        ));
        assert_eq!(*transcript.inspection.lock().unwrap_err().into_inner(), before);
        assert_eq!(transcript.transcript_bytes(), bytes);
    }

    #[test]
    fn test_challenge_origins() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"challenge-origins");
        transcript.add_generator("g", Value::int(2)).unwrap();
        transcript.add_message("m", Value::int(3)).unwrap();
        let before = transcript.inspection.lock().unwrap().clone();
        assert!(transcript.record_challenges::<Sha3_256>(
            &["e", "e"], &["g", "m"], &BigInt::from(97)
        ).is_err());
        assert_eq!(*transcript.inspection.lock().unwrap(), before);
        let values = transcript.record_challenges::<Sha3_256>(
            &["e1", "e2"], &["g", "m"], &BigInt::from(97)
        ).unwrap();
        assert_ne!(values[0].origin_id, values[1].origin_id);
        let origins = transcript.inspection.lock().unwrap();
        assert_eq!(origins.len(), before.len() + 2);
        for (value, label) in values.iter().zip(["e1", "e2"]) {
            assert_eq!(transcript.elements[label].round, 0);
            assert!(origins[value.origin_id.unwrap()].submitted_rounds.is_none());
            assert_eq!(origins[value.origin_id.unwrap()].latest_challenge, Some(0));
            assert_eq!(origins[value.origin_id.unwrap()].operation, OriginOperation::Registered {
                element_index: transcript.elements[label].index,
                source: None
            });
        }
        assert_eq!(transcript.round, 1);
    }

    #[test]
    fn test_poisoned_inspection() {
        use sha3::Sha3_256;

        let mut transcript = test_transcript(b"poisoned-inspection");
        transcript.add_generator("g", Value::int(2)).unwrap();
        let message = transcript.add_message("m", Value::int(3)).unwrap();
        let before = transcript.inspection.lock().unwrap().clone();
        let bytes = transcript.transcript_bytes().to_vec();
        let inspection = Arc::clone(&transcript.inspection);
        let panic = std::panic::catch_unwind(|| {
            let _guard = inspection.lock().unwrap();
            panic!("test poisoned inspection state");
        });
        assert!(panic.is_err());
        assert!(matches!(&message * &message, Err(TranscriptError::InspectionStatePoisoned)));
        assert!(matches!(
            transcript.add_message("new", Value::int(5)),
            Err(TranscriptError::InspectionStatePoisoned)
        ));
        assert!(matches!(
            transcript.add_response("r", message.clone()),
            Err(TranscriptError::InspectionStatePoisoned)
        ));
        assert!(matches!(
            transcript.record_challenges::<Sha3_256>(&["e1", "e2"], &["g", "m"], &BigInt::from(97)),
            Err(TranscriptError::InspectionStatePoisoned)
        ));
        assert_eq!(transcript.transcript_bytes(), bytes);
        assert_eq!(transcript.round, 0);
        assert_eq!(transcript.index, 2);
        assert_eq!(*transcript.inspection.lock().unwrap_err().into_inner(), before);
    }
}
