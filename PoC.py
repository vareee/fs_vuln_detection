from typing import Dict, Set, List, Tuple
from enum import Enum
import uuid
from ecpy.curves import Curve, Point
import hashlib, random


class TranscriptError(Exception):
    pass

class CrossTranscriptError(Exception):
    pass

class CrossRoundError(Exception):
    pass

class ObjectCategory(Enum):
    Commitment = "commitment"
    Pubkey = "pubkey"
    Message = "message"
    Challenge = "challenge"
    Response = "response"
    Generator = "generator"


class TranscriptInspector:
    def __init__(self):
        self.transcript_id = uuid.uuid4()
        self.elements: Dict[str, Tuple[str, ObjectCategory, int]] = {}
        self.challenges: Dict[str, Set[str]] = {}
        self.index: int = 0
        self.round: int = 0
        self.challenges_mul: Dict[str, Set[str]] = {}

    class TaggedValue:
        def __init__(self, value, tid):
            self.value = value
            self.transcript_id = tid

        @property
        def x(self):
            return self.value.x

        @property
        def y(self):
            return self.value.y

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

    # add object to transcript (who did it, its category (pubkey, challenge, ...), its number in transcript and round number)
    def add(self, name: str, subject: str, category: ObjectCategory, value):
        if name in self.elements:
            return
        if category in (ObjectCategory.Commitment, ObjectCategory.Pubkey) and len(self.challenges) > 0:
            raise TranscriptError(
                            f"Element '{name}' (category={category.value}) was added after the first challenge "
                            f"and was NOT included in that challenge."
                        )
        
        tagged = self.tag(value)
        self.elements[name] = (subject, category, self.index, self.round, tagged)
        self.index += 1
        self.challenges_mul[name] = set()
        return tagged

    # func to imitate multiplication of objects (as in PoC there is no direct interaction between objects), used to detect errors in cross-round interaction
    def imitate_mul(self, object_name: str, challenge_name: str):
        if object_name not in self.elements:
            raise ValueError(f"Unknown object '{object_name}'")
        
        if challenge_name not in self.challenges:
            raise ValueError(f"Unknown challenge '{challenge_name}'")
        
        self.challenges_mul[object_name].add(challenge_name)

    #func to create a challenge (imitation of it)
    def record_challenge(self, challenge_name: str, used_names: List[str], value):
        used_set = set(used_names)
        if len(used_names) < len(self.elements) - len(self.challenges):
            raise ValueError(
                    f"Not every prover's message was included in the challenge!" # error if plaintext was not hashed in the first challenge
                )
        
        pt_found = False
        generator_found = False
        for n in used_set:
            if n not in self.elements:
                raise ValueError(
                    f"Challenge '{challenge_name}' uses unknown element '{n}'!" # error if an argument was not declared in transcript
                )
            _, category, _, _,_ = self.elements[n]
            if category == ObjectCategory.Message:
                pt_found = True
            elif category == ObjectCategory.Generator:
                generator_found = True
        
        if len(self.challenges) == 0:
            if not pt_found:
                raise ValueError(
                        f"Plaintext was not included in the first challenge!" # error if plaintext was not hashed in the first challenge
                    )
            if not generator_found:
                raise ValueError(
                        f"Generator-element was not included in the first challenge!" # error if generator (of a group or an ellicptic curve) was not hashed in the first challenge
                    )

        self.challenges[challenge_name] = used_set
        tagged = self.add(challenge_name, subject="verifier", category=ObjectCategory.Challenge, value=value)
        self.round += 1
        return tagged

    # func to detect errors in cross-round interaction
    def check_cross_round_interaction(self, object1: str, object2: str):
        _, _, _, round_1, _ = self.elements[object1]
        _, _, _, round_2, _ = self.elements[object2]

        if round_1 == round_2:
            return

        mul_1 = self.challenges_mul.get(object1, set()) # list of challenges object1 was multiplied by
        mul_2 = self.challenges_mul.get(object2, set()) # list of challenges object2 was multiplied by
        other_round_challenges_1 = {challenge for challenge in self.challenges if self.elements[challenge][3] == round_2} # list of challenges in round of object2
        other_round_challenges_2 = {challenge for challenge in self.challenges if self.elements[challenge][3] == round_1} # list of challenges in round of object1

        safe_1 = not mul_1.isdisjoint(other_round_challenges_1) # check if object1 was multiplied by any challenge in round of object2
        safe_2 = not mul_2.isdisjoint(other_round_challenges_2)# check if object2 was multiplied by any challenge in round of object1

        #if no then raise exception
        if not (safe_1 or safe_2):
            raise CrossRoundError(
                f"Objects '{object1}' and '{object2}' from different rounds interact "
                f"but neither of them is multiplied by a challenge from the other's round!"
            )


curve = Curve.get_curve("secp256k1")
G: Point = curve.generator
curve_order: int = curve.order
message = b"hello schnorr batching"

def i2b32(x: int) -> bytes:
    return int(x % curve.field).to_bytes(32, "big")

def serialize_point(point):
    return i2b32(point.value.x) + i2b32(point.value.y)


# example of safe transcript
try:
    transcript_safe = TranscriptInspector()

    a1 = random.randint(1, curve_order - 1)
    A1 = transcript_safe.add(name="A1", subject="prover1", category=ObjectCategory.Pubkey, value=G*a1)

    k1 = random.randint(1, curve_order - 1)
    R1 = transcript_safe.add(name="R1", subject="prover1", category=ObjectCategory.Commitment, value=G*k1)
    
    a2 = random.randint(1, curve_order - 1)
    A2 = transcript_safe.add(name="A2", subject="prover2", category=ObjectCategory.Pubkey, value=G*a2)

    k2 = random.randint(1, curve_order - 1)
    R2 = transcript_safe.add(name="R2", subject="prover2", category=ObjectCategory.Commitment, value=G*k2)

    msg_rnd = random.randint(1, curve_order - 1)
    msg = transcript_safe.add(name="message", subject="prover2", category=ObjectCategory.Message, value=G*msg_rnd)
    
    data = serialize_point(A1) + serialize_point(R1) + serialize_point(A2) + serialize_point(R2) + serialize_point(msg)
    e = transcript_safe.record_challenge(challenge_name="e", used_names=["A1","A2","R1","R2","message"],
                                    value=int.from_bytes(hashlib.sha256(data).digest(), "big")%curve_order)
    
    print("No Fiat-Shamir heuristic vulnerability detected.")
except Exception as e:
    print("Detection:", e)


print("----------------")

# example of transcript with TranscriptError
try:
    transcript_vulnerability = TranscriptInspector()

    msg_rnd = random.randint(1, curve_order - 1)
    msg = transcript_vulnerability.add(name="msg", subject="prover1", category=ObjectCategory.Message, value=G*msg_rnd)

    a1 = random.randint(1, curve_order - 1)
    A1 = transcript_vulnerability.add(name="A1", subject="prover1", category=ObjectCategory.Pubkey, value=G*a1)

    k1 = random.randint(1, curve_order - 1)
    R1 = transcript_vulnerability.add(name="R1", subject="prover1", category=ObjectCategory.Commitment, value=G*k1)

    data = serialize_point(A1) + serialize_point(R1) + serialize_point(msg)
    e1 = transcript_vulnerability.record_challenge(challenge_name="e1", used_names=["A1", "R1", "msg"],
                                                value=int.from_bytes(hashlib.sha256(data).digest(), "big")%curve_order)

    a2 = random.randint(1, curve_order - 1)
    A2 = transcript_vulnerability.add(name="A2", subject="prover2", category=ObjectCategory.Pubkey, value=G*a2,)

    k2 = random.randint(1, curve_order - 1)
    R2 = transcript_vulnerability.add(name="R2", subject="prover2", category=ObjectCategory.Commitment, value=G*k2)


    data = serialize_point(A1) + serialize_point(R1) + serialize_point(A2) + serialize_point(R2) + serialize_point(msg)
    e2 = transcript_vulnerability.record_challenge(challenge_name="e2", used_names=["A1", "R1", "A2", "R2", "msg"],
                                                value=int.from_bytes(hashlib.sha256(data).digest(), "big")%curve_order)

    print("No Fiat-Shamir heuristic vulnerability detected.")
except Exception as e:
    print("Detected:", e)


print("----------------")

# example of cross transcript interaction with error
def bad_verify(R, A, s, e):
    LHS = s * G
    RHS = R + e * A
    return LHS.value == RHS.value

try:
    transcript1 = TranscriptInspector()

    msg1 = transcript1.add(name="msg", subject="prover", 
                                        category=ObjectCategory.Message, value=message)

    a1 = random.randint(1, curve_order - 1)
    A1 = transcript1.add(name="A1", subject="prover", category=ObjectCategory.Pubkey, value=G*a1)

    k1 = random.randint(1, curve_order - 1)
    R1 = transcript1.add(name="R1", subject="prover", category=ObjectCategory.Commitment, value=G*k1)

    data = serialize_point(R1) + serialize_point(A1) + message
    e1 = transcript1.record_challenge(challenge_name="e1", used_names=["R1", "A1", "msg"], 
                                      value=int.from_bytes(hashlib.sha256(data).digest(), "big")%curve_order)

    s1 = transcript1.add(name="s1", subject="prover", category=ObjectCategory.Message, 
                    value=(k1+e1.value*a1)%curve_order)


    transcript2 = TranscriptInspector()

    msg2 = transcript2.add(name="msg", subject="prover", 
                                        category=ObjectCategory.Message, value=message)

    a2 = random.randint(1, curve_order - 1)
    A2 = transcript2.add(name="A2", subject="prover", category=ObjectCategory.Pubkey, value=G*a2)

    k2 = random.randint(1, curve_order - 1)
    R2 = transcript2.add(name="R2", subject="prover", category=ObjectCategory.Commitment, value=G*k2)

    data = serialize_point(R2) + serialize_point(A2)
    e2 = transcript2.record_challenge(challenge_name="e2", used_names=["R2", "A2", "msg"], 
                                 value=int.from_bytes(hashlib.sha256(data).digest(), "big")%curve_order)

    s2 = transcript2.add(name="s2", subject="prover", category=ObjectCategory.Message, 
                         value=(k2+e2.value*a2)%curve_order)

    valid = bad_verify(R2, A2, s1, e1)
    print("No Fiat-Shamir heuristic vulnerability detected.")
except Exception as e:
    print("Detected:", e)


print("----------------")

# example of cross round object ineraction with error
try:
    transcript_round_vuln = TranscriptInspector()

    msg_rnd = random.randint(1, curve_order - 1)
    msg = transcript_round_vuln.add(name="msg", subject="prover", category=ObjectCategory.Message, value=G*msg_rnd)

    a = random.randint(1, curve_order - 1)
    A = transcript_round_vuln.add(name="A", subject="prover", category=ObjectCategory.Pubkey, value=G*a)

    k = random.randint(1, curve_order - 1)
    R = transcript_round_vuln.add(name="R", subject="prover", category=ObjectCategory.Commitment, value=G*k)
    
    data = serialize_point(R) + serialize_point(A) + serialize_point(msg)
    e1 = transcript_round_vuln.record_challenge(challenge_name="e1", used_names=["A", "R", "msg"], 
                                        value=int.from_bytes(hashlib.sha256(data).digest(), "big")%curve_order)

    Z1 = transcript_round_vuln.add(name="Z1", subject="prover", category=ObjectCategory.Response, 
                                   value=A-e1*msg)

    data = serialize_point(R) + serialize_point(A) + serialize_point(Z1)
    e2 = transcript_round_vuln.record_challenge(challenge_name="e2", used_names=["A", "R", "Z1"],
                                           value=int.from_bytes(hashlib.sha256(data).digest(), "big")%curve_order)
    
    transcript_round_vuln.add(name="Z2", subject="prover", category=ObjectCategory.Response, 
                              value=A-e2*msg)
    
    transcript_round_vuln.check_cross_round_interaction("Z2", "A")
    print("No Fiat-Shamir heuristic vulnerability detected.")
except Exception as e:
    print("Detected:", e)
