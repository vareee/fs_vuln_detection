from typing import Dict, Set, List, Tuple
from enum import Enum
import uuid
from ecpy.curves import Curve, Point
import hashlib, random


class TranscriptError(Exception):
    pass

class CrossTranscriptError(Exception):
    pass

class ObjectCategory(Enum):
    Commitment = "commitment"
    Pubkey = "pubkey"
    Message = "message"
    Challenge = "challenge"


class TranscriptInspector:
    def __init__(self):
        self.transcript_id = uuid.uuid4()
        self.elements: Dict[str, Tuple[str, ObjectCategory, int]] = {}
        self.challenges: Dict[str, Set[str]] = {}
        self.index: int = 0
        self.round: int = 0

    class TaggedValue:
        def __init__(self, value, tid):
            self.value = value
            self.transcript_id = tid

        def _ensure_same_transcript_id(self, other):
            if isinstance(other, TranscriptInspector.TaggedValue) and self.transcript_id != other.transcript_id:
                raise CrossTranscriptError(
                    f"Objects from different transcripts cannot interact!"
                )

        def __add__(self, other):
            if isinstance(other, TranscriptInspector.TaggedValue):
                self._ensure_same_transcript_id(other)
                return TranscriptInspector.TaggedValue(self.value + other.value, self.transcript_id)
            
            return TranscriptInspector.TaggedValue(self.value + other, self.transcript_id)

        def __sub__(self, other):
            if isinstance(other, TranscriptInspector.TaggedValue):
                self._ensure_same_transcript_id(other)
                return TranscriptInspector.TaggedValue(self.value - other.value, self.transcript_id)
            
            return TranscriptInspector.TaggedValue(self.value - other, self.transcript_id)

        def __mul__(self, other):
            if isinstance(other, TranscriptInspector.TaggedValue):
                self._ensure_same_transcript_id(other)
                return TranscriptInspector.TaggedValue(self.value * other.value, self.transcript_id)
            
            return TranscriptInspector.TaggedValue(self.value * other, self.transcript_id)

        def __rmul__(self, other):
            return self.__mul__(other)

    def tag(self, value):
        return TranscriptInspector.TaggedValue(value, self.transcript_id)

    def add(self, name: str, subject: str, category: ObjectCategory):
        if name in self.elements:
            return
        
        self.elements[name] = (subject, category, self.index, self.round)
        self.index += 1

    def record_challenge(self, challenge_name: str, used_names: List[str]):
        used_set = set(used_names)
        for n in used_set:
            if n not in self.elements:
                raise ValueError(
                    f"Challenge '{challenge_name}' uses unknown element '{n}'!"
                )

        self.challenges[challenge_name] = used_set
        self.add(challenge_name, subject="verifier", category=ObjectCategory.Challenge)
        self.round += 1

    def analyze_verification(self, verification_used: List[str], challenge_names: List[str]):
        for name in verification_used:
            if name not in self.elements:
                raise ValueError(f"Verification references unknown element '{name}'!")

            _, category, index, _ = self.elements[name]
            if category in (ObjectCategory.Commitment, ObjectCategory.Pubkey):
                for challenge_name in challenge_names:
                    if challenge_name not in self.challenges:
                        raise ValueError(f"Challenge '{challenge_name}' not recorded!")

                    _, _, challenge_index, _ = self.elements[challenge_name]
                    if index > challenge_index and name not in self.challenges[challenge_name]:
                        raise TranscriptError(
                            f"Element '{name}' (category={category.value}) "
                            f"was added at index {index} after challenge '{challenge_name}' "
                            f"(index {challenge_index}) but was NOT included in that challenge."
                        )


curve = Curve.get_curve("secp256k1")
G: Point = curve.generator
curve_order: int = curve.order
message = b"hello schnorr batching"

def i2b32(x: int) -> bytes:
    return int(x % curve.field).to_bytes(32, "big")

def serialize_point(point):
    return i2b32(point.value.x) + i2b32(point.value.y)

def bad_verify(R, A, s, e):
    LHS = s * G
    RHS = R + e * A
    return LHS.value == RHS.value

# example of safe transcript
transcript_safe = TranscriptInspector()

transcript_safe.add("A1", "prover1", ObjectCategory.Pubkey)
transcript_safe.add("R1", "prover1", ObjectCategory.Commitment)
transcript_safe.add("A2", "prover2", ObjectCategory.Pubkey)
transcript_safe.add("R2", "prover2", ObjectCategory.Commitment)
transcript_safe.add("message", "verifier", ObjectCategory.Message)
transcript_safe.record_challenge("e", used_names=["A1","A2","R1","R2","message"])

try:
    transcript_safe.analyze_verification(verification_used=["A1","A2","R1","R2","message"], challenge_names=["e"])
    print("No Fiat-Shamir heuristic vulnerability detected.")
except TranscriptError as e:
    print("Detection:", e)


print("----------------")

# example of transcript with TranscriptError
transcript_vulnerability = TranscriptInspector()

transcript_vulnerability.add(name="A1", subject="prover1", category=ObjectCategory.Pubkey)
transcript_vulnerability.add(name="R1", subject="prover1", category=ObjectCategory.Commitment)
transcript_vulnerability.record_challenge(challenge_name="c", used_names=["A1", "R1"])

transcript_vulnerability.add(name="A2", subject="prover2", category=ObjectCategory.Pubkey)
transcript_vulnerability.add(name="R2", subject="prover2", category=ObjectCategory.Commitment)
transcript_vulnerability.add(name="msg", subject="verifier", category=ObjectCategory.Message)
transcript_vulnerability.record_challenge(challenge_name="e", used_names=["A1", "R1", "A2", "R2", "msg"])

try:
    transcript_vulnerability.analyze_verification(verification_used=["A1", "A2", "R1", "R2", "msg"], challenge_names=["c", "e"])
    print("No Fiat-Shamir heuristic vulnerability detected.")
except TranscriptError as e:
    print("Detected:", e)


print("----------------")

# example of cross transcript interaction
transcript1 = TranscriptInspector()

a1 = random.randint(1, curve_order-1)
A1 = transcript1.tag(G * a1)
transcript1.add(name="A1", subject="prover", category=ObjectCategory.Pubkey)

k1 = random.randint(1, curve_order-1)
R1 = transcript1.tag(G * k1)
transcript1.add(name="R1", subject="prover", category=ObjectCategory.Commitment)

data = serialize_point(R1) + serialize_point(A1) + message
e1 = transcript1.tag(int.from_bytes(hashlib.sha256(data).digest(), "big") % curve_order)
transcript1.record_challenge(challenge_name="e1", used_names=["R1", "A1"])

s1 = transcript1.tag((k1 + e1.value * a1) % curve_order)
transcript1.add(name="s1", subject="prover", category=ObjectCategory.Message)


transcript2 = TranscriptInspector()

a2 = random.randint(1, curve_order-1)
A2 = transcript2.tag(G * a2)
transcript2.add("A2", "prover", ObjectCategory.Pubkey)

k2 = random.randint(1, curve_order-1)
R2 = transcript2.tag(G * k2)
transcript2.add("R2", "prover", ObjectCategory.Commitment)

data = serialize_point(R2) + serialize_point(A2)
e2 = transcript2.tag(int.from_bytes(hashlib.sha256(data).digest(), "big") % curve_order)
transcript2.record_challenge(challenge_name="e2", used_names=["R2", "A2"])

s2 = transcript2.tag((k2 + e2.value * a2) % curve_order)
transcript2.add("s2", "prover", ObjectCategory.Message)

try:
    valid = bad_verify(R2, A2, s1, e1)
    print("Verifier returned:", valid)

except CrossTranscriptError as e:
    print("Detected:", e)
