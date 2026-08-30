import random
from ecpy.curves import Curve, Point
from PoC import TranscriptManager, H, ObjectCategory


curve = Curve.get_curve("secp256k1")
G: Point = curve.generator
curve_order: int = curve.order

def i2b32(x: int) -> bytes:
    return int(x % curve.field).to_bytes(32, "big")

def serialize_point(point):
    if isinstance(point.value, Point) or isinstance(point.value, TranscriptManager.TaggedValue):
        return i2b32(point.value.x) + i2b32(point.value.y)
    elif isinstance(point.value, int):
        return i2b32(point.value) + i2b32(point.value.y)
    
# example of safe transcript
try:
    transcript_safe = TranscriptManager()

    G1 = transcript_safe.add(name="gen", subject="prover1", category=ObjectCategory.Generator, value=G)

    a1 = transcript_safe.add(name="a1", subject="prover1", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    A1 = transcript_safe.add(name="A1", subject="prover1", category=ObjectCategory.Pubkey, value=G1*a1)

    k1 = transcript_safe.add(name="k1", subject="prover1", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    R1 = transcript_safe.add(name="R1", subject="prover1", category=ObjectCategory.Commitment, value=G1*k1)
    
    a2 = transcript_safe.add(name="a2", subject="prover2", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    A2 = transcript_safe.add(name="A2", subject="prover2", category=ObjectCategory.Pubkey, value=G1*a2)

    k2 = transcript_safe.add(name="k2", subject="prover2", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    R2 = transcript_safe.add(name="R2", subject="prover2", category=ObjectCategory.Commitment, value=G1*k2)

    msg_rnd = transcript_safe.add(name="msg_rnd", subject="prover2", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    msg = transcript_safe.add(name="message", subject="prover2", category=ObjectCategory.Message, value=G1*msg_rnd)
    
    data = serialize_point(A1) + serialize_point(R1) + serialize_point(A2) + serialize_point(R2) + serialize_point(msg) + serialize_point(G1)
    e = transcript_safe.record_challenge(challenge_name="e", used_names=["A1","A2","R1","R2","message", "gen"], value=H(data, curve_order))
    
    print("No Fiat-Shamir heuristic vulnerability detected.")
except Exception as e:
    print("Detection:", e)


print("----------------")

# example of transcript with TranscriptError
try:
    transcript_vulnerability = TranscriptManager()

    G1 = transcript_vulnerability.add(name="gen", subject="prover1", category=ObjectCategory.Generator, value=G)

    msg_rnd = transcript_vulnerability.add(name="msg_rnd", subject="prover1", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    msg = transcript_vulnerability.add(name="msg", subject="prover1", category=ObjectCategory.Message, value=G1*msg_rnd)

    a1 = transcript_vulnerability.add(name="a1", subject="prover1", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    A1 = transcript_vulnerability.add(name="A1", subject="prover1", category=ObjectCategory.Pubkey, value=G1*a1)

    k1 = transcript_vulnerability.add(name="k1", subject="prover1", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    R1 = transcript_vulnerability.add(name="R1", subject="prover1", category=ObjectCategory.Commitment, value=G1*k1)

    data = serialize_point(A1) + serialize_point(R1) + serialize_point(msg) + serialize_point(G1)
    e1 = transcript_vulnerability.record_challenge(challenge_name="e1", used_names=["A1", "R1", "msg", "gen"], value=H(data, curve_order))

    a2 = transcript_vulnerability.add(name="a2", subject="prover2", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    A2 = transcript_vulnerability.add(name="A2", subject="prover2", category=ObjectCategory.Pubkey, value=G1*a2,)

    k2 = transcript_vulnerability.add(name="k2", subject="prover2", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    R2 = transcript_vulnerability.add(name="R2", subject="prover2", category=ObjectCategory.Commitment, value=G1*k2)


    data = serialize_point(A1) + serialize_point(R1) + serialize_point(A2) + serialize_point(R2) + serialize_point(msg)
    e2 = transcript_vulnerability.record_challenge(challenge_name="e2", used_names=["A1", "R1", "A2", "R2", "msg"], value=H(data, curve_order))

    print("No Fiat-Shamir heuristic vulnerability detected.")
except Exception as e:
    print("Detected:", e)


print("----------------")

# example of cross transcript interaction with error
def bad_verify(R, A, s, e, G):
    LHS = s * G
    RHS = R + e * A
    return LHS.value == RHS.value

try:
    transcript1 = TranscriptManager()

    G1 = transcript1.add(name="gen", subject="prover", category=ObjectCategory.Generator, value=G)

    msg_rnd1 = transcript1.add(name="msg_rnd1", subject="prover", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    msg1 = transcript1.add(name="msg", subject="prover", category=ObjectCategory.Message, value=G1*msg_rnd1)

    a1 = transcript1.add(name="a1", subject="prover", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    A1 = transcript1.add(name="A1", subject="prover", category=ObjectCategory.Pubkey, value=G1*a1)

    k1 = transcript1.add(name="k1", subject="prover", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    R1 = transcript1.add(name="R1", subject="prover", category=ObjectCategory.Commitment, value=G1*k1)

    data = serialize_point(R1) + serialize_point(A1) + serialize_point(msg1) + serialize_point(G1)
    e1 = transcript1.record_challenge(challenge_name="e1", used_names=["R1", "A1", "msg", "gen"], value=H(data, curve_order))

    s1 = transcript1.add(name="s1", subject="prover", category=ObjectCategory.Message, 
                    value=(k1+e1*a1)%curve_order)


    transcript2 = TranscriptManager()

    G2 = transcript2.add(name="gen", subject="prover", category=ObjectCategory.Generator, value=G)

    msg_rnd2 = transcript2.add(name="msg_rnd2", subject="prover", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    msg2 = transcript2.add(name="msg", subject="prover", category=ObjectCategory.Message, value=G2*msg_rnd2)

    a2 = transcript2.add(name="a2", subject="prover", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    A2 = transcript2.add(name="A2", subject="prover", category=ObjectCategory.Pubkey, value=G2*a2)

    k2 = transcript2.add(name="k2", subject="prover", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    R2 = transcript2.add(name="R2", subject="prover", category=ObjectCategory.Commitment, value=G2*k2)

    data = serialize_point(R2) + serialize_point(A2) + serialize_point(msg2) + serialize_point(G2)
    e2 = transcript2.record_challenge(challenge_name="e2", used_names=["R2", "A2", "msg", "gen"], value=H(data, curve_order))

    s2 = transcript2.add(name="s2", subject="prover", category=ObjectCategory.Message, 
                         value=(k2+e2*a2)%curve_order)

    valid = bad_verify(R2, A2, s1, e1, G2)
    print("No Fiat-Shamir heuristic vulnerability detected.")
except Exception as e:
    print("Detected:", e)


print("----------------")

# example of cross round object ineraction with error
try:
    transcript_round_vuln = TranscriptManager()

    G1 = transcript_round_vuln.add(name="gen", subject="prover2", category=ObjectCategory.Generator, value=G)

    msg_rnd = transcript_round_vuln.add(name="msg_rnd", subject="prover", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    msg = transcript_round_vuln.add(name="msg", subject="prover", category=ObjectCategory.Message, value=G1*msg_rnd)

    a = transcript_round_vuln.add(name="a", subject="prover", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    A = transcript_round_vuln.add(name="A", subject="prover", category=ObjectCategory.Pubkey, value=G1*a)

    k = transcript_round_vuln.add(name="k", subject="prover", category=ObjectCategory.Constant, value=random.randint(1, curve_order - 1))
    R = transcript_round_vuln.add(name="R", subject="prover", category=ObjectCategory.Commitment, value=G1*k)
    
    data = serialize_point(R) + serialize_point(A) + serialize_point(msg) + serialize_point(G1)
    e1 = transcript_round_vuln.record_challenge(challenge_name="e1", used_names=["A", "R", "msg", "gen"], value=H(data, curve_order))

    Z1 = transcript_round_vuln.add(name="Z1", subject="prover", category=ObjectCategory.Response, value=A-e1*msg)

    data = serialize_point(R) + serialize_point(A) + serialize_point(msg) + serialize_point(G1) + serialize_point(Z1)
    e2 = transcript_round_vuln.record_challenge(challenge_name="e2", used_names=["A", "R", "msg", "gen", "Z1"], value=H(data, curve_order))
    
    Z2 = transcript_round_vuln.add(name="Z2", subject="prover", category=ObjectCategory.Response, value=A-e2*msg)
    
    transcript_round_vuln.check_cross_round_interaction("Z2", "A")
    print("No Fiat-Shamir heuristic vulnerability detected.")
except Exception as e:
    print("Detected:", e)


print("----------------")

# example of interaction with not constants
try:
    transcript_safe = TranscriptManager()

    G1 = transcript_safe.add(name="gen", subject="prover1", category=ObjectCategory.Generator, value=G)

    a1 = random.randint(1, curve_order - 1)
    A1 = transcript_safe.add(name="A1", subject="prover1", category=ObjectCategory.Pubkey, value=G1*a1)
    
    k1 = random.randint(1, curve_order - 1)
    R1 = transcript_safe.add(name="R1", subject="prover1", category=ObjectCategory.Commitment, value=G1*k1)
    
    a2 = random.randint(1, curve_order - 1)
    A2 = transcript_safe.add(name="A2", subject="prover2", category=ObjectCategory.Pubkey, value=G1*a2)

    k2 = random.randint(1, curve_order - 1)
    R2 = transcript_safe.add(name="R2", subject="prover2", category=ObjectCategory.Commitment, value=G1*k2)

    msg_rnd = random.randint(1, curve_order - 1)
    msg = transcript_safe.add(name="message", subject="prover2", category=ObjectCategory.Message, value=G1*msg_rnd)
    
    data = serialize_point(A1) + serialize_point(R1) + serialize_point(A2) + serialize_point(R2) + serialize_point(msg) + serialize_point(G1)
    e = transcript_safe.record_challenge(challenge_name="e", used_names=["A1","A2","R1","R2","message", "gen"], value=H(data, curve_order))
    
    print("No Fiat-Shamir heuristic vulnerability detected.")
except Exception as e:
    print("Detection:", e)

print("----------------")
