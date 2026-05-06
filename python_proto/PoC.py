from typing import Dict, Set, List, Tuple
from enum import Enum
import uuid
import hashlib


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
    Constant = "const"


class TranscriptManager:
    def __init__(self):
        self.transcript_id = uuid.uuid4()
        self.elements: Dict[str, Tuple[str, ObjectCategory, int]] = {}
        self.challenges: Dict[str, Set[str]] = {}
        self.index: int = 0
        self.round: int = 0
        self.challenges_mul: Dict[str, Set[str]] = {}
        self.constant_num: int = 0

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
            if isinstance(other, TranscriptManager.TaggedValue) and self.transcript_id != other.transcript_id:
                raise CrossTranscriptError(f"Objects from different transcripts cannot interact!")

        def __add__(self, other):
            if isinstance(other, TranscriptManager.TaggedValue):
                self._ensure_same_transcript_id(other)
                left = self.value
                right = other.value
                while isinstance(left, TranscriptManager.TaggedValue):
                    left = left.value
                while isinstance(right, TranscriptManager.TaggedValue):
                    right = right.value
            else:
                left = self.value
                while isinstance(left, TranscriptManager.TaggedValue):
                    left = left.value
                right = other

            return TranscriptManager.TaggedValue(left + right, self.transcript_id)     

        def __sub__(self, other):
            if isinstance(other, TranscriptManager.TaggedValue):
                self._ensure_same_transcript_id(other)

                left = self.value
                right = other.value
                while isinstance(left, TranscriptManager.TaggedValue):
                    left = left.value
                while isinstance(right, TranscriptManager.TaggedValue):
                    right = right.value
            else:
                left = self.value
                while isinstance(left, TranscriptManager.TaggedValue):
                    left = left.value
                right = other

            return TranscriptManager.TaggedValue(left - right, self.transcript_id)

        def __mul__(self, other):
            if isinstance(other, TranscriptManager.TaggedValue):
                self._ensure_same_transcript_id(other)

                left = self.value
                right = other.value
                while isinstance(left, TranscriptManager.TaggedValue):
                    left = left.value
                while isinstance(right, TranscriptManager.TaggedValue):
                    right = right.value

                return TranscriptManager.TaggedValue(left * right, self.transcript_id)
            
            raise ValueError("Interaction with an element not from the transcript!")

        def __rmul__(self, other):
            return self.__mul__(other)
        
        def __mod__(self, other):
            if isinstance(other, TranscriptManager.TaggedValue):
                self._ensure_same_transcript_id(other)

                left = self.value
                right = other.value
                while isinstance(left, TranscriptManager.TaggedValue):
                    left = left.value
                while isinstance(right, TranscriptManager.TaggedValue):
                    right = right.value
            else:
                left = self.value
                right = other 
                while isinstance(left, TranscriptManager.TaggedValue):
                    left = left.value

            if isinstance(left, int) and isinstance(right, int):
                    return TranscriptManager.TaggedValue(left % right, self.transcript_id)
            raise TypeError(f"TaggedValue with value of {type(self.value)} cannot be divided by modulo!")
        
        def __rmod__(self, other):
            if isinstance(other, TranscriptManager.TaggedValue):
                self._ensure_same_transcript_id(other)

                left = other.value
                right = self.value
                while isinstance(left, TranscriptManager.TaggedValue):
                    left = left.value
                while isinstance(right, TranscriptManager.TaggedValue):
                    right = right.value
            else:
                left = other
                right = self.value
                while isinstance(right, TranscriptManager.TaggedValue):
                    right = right.value
            
            if isinstance(right, int) and isinstance(left, int):
                return TranscriptManager.TaggedValue(left % right, self.transcript_id)
            raise TypeError(f"TaggedValue with value of {type(self.value)} cannot be used as modulo!")
        
        def __int__(self):
            if isinstance(self.value, int):
                return self.value
            
            raise TypeError(f"TaggedValue with value of {type(self.value)} cannot be used as integer!")
        
        def __index__(self):
            return int(self)
        
        def __pow__(self, other, module=None):
            if isinstance(other, TranscriptManager.TaggedValue):
                self._ensure_same_transcript_id(other)

                left = self.value
                right = other.value
                while isinstance(left, TranscriptManager.TaggedValue):
                    left = left.value
                while isinstance(right, TranscriptManager.TaggedValue):
                    right = right.value

                if module:
                    while isinstance(module, TranscriptManager.TaggedValue):
                        module = module.value

                    return TranscriptManager.TaggedValue(pow(left, right, module), self.transcript_id)
                else:
                    return TranscriptManager.TaggedValue(pow(left, right), self.transcript_id)
            
            raise ValueError("Interaction with an element not from the transcript!")
        
        def __rpow__(self, base):
            if isinstance(base, TranscriptManager.TaggedValue):
                self._ensure_same_transcript_id(base)

                left = base.value
                right = self.value
                while isinstance(left, TranscriptManager.TaggedValue):
                    left = left.value
                while isinstance(right, TranscriptManager.TaggedValue):
                    right = right.value
                    
                if isinstance(right, int):
                    return pow(left, right)
                
                raise TypeError(f"TaggedValue with value of {type(self.value)} cannot be used as exponent!")
            
            raise ValueError("Interaction with an element not from the transcript!")

        def __iter__(self):
            if isinstance(self.value, list):
                return iter(self.value)
            
            raise TypeError(f"TaggedValue with value of {type(self.value)} cannot be iterated!")
        
        def __getitem__(self, i):
            if isinstance(self.value, list):
                return self.value[i]
            
            raise TypeError(f"TaggedValue with value of {type(self.value)} cannot be indexed")

    def tag(self, value):
        return TranscriptManager.TaggedValue(value, self.transcript_id)

    # add object to transcript (who did it, its category (pubkey, challenge, ...), its number in transcript and round number)
    def add(self, name: str, subject: str, category: ObjectCategory, value):
        if name in self.elements:
            return
        if category in (ObjectCategory.Commitment, ObjectCategory.Pubkey) and len(self.challenges) > 0:
            raise TranscriptError(
                            f"Element '{name}' (category={category.value}) was added after the first challenge "
                            f"and was not included in that challenge."
                        )
        if isinstance(value, list):
            temp = [self.tag(x) for x in value]
        else:
            temp = value

        tagged = self.tag(temp)
        self.elements[name] = (subject, category, self.index, self.round, tagged)
        if category == ObjectCategory.Constant:
            self.constant_num += 1
        self.index += 1
        self.challenges_mul[name] = set()
        return tagged

    #func to create a challenge (imitation of it)
    def record_challenge(self, challenge_name: str, used_names: List[str], value):
        used_set = set(used_names)
        if len(used_set) != len(used_names):
            raise ValueError(f"Challenge has two or more similar objects to hash!")

        if len(used_names) < len(self.elements) - len(self.challenges) - self.constant_num:
            raise ValueError(f"Not every prover's message was included in the challenge!")
        
        pt_found = False
        generator_found = False
        for n in used_set:
            if n not in self.elements:
                raise ValueError(f"Challenge '{challenge_name}' uses unknown element '{n}'!") # error if an argument was not declared in transcript
            
            _, category, _, _,_ = self.elements[n]
            if category == ObjectCategory.Message:
                pt_found = True
            elif category == ObjectCategory.Generator:
                generator_found = True
        
        if len(self.challenges) == 0:
            if not pt_found: # error if plaintext was not hashed in the first challenge
                raise ValueError("Plaintext was not included in the first challenge!") 
            if not generator_found: # error if generator (of a group or an ellicptic curve) was not hashed in the first challenge
                raise ValueError("Generator-element was not included in the first challenge!")

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

def H(data: bytes, curve_order: int) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % curve_order
