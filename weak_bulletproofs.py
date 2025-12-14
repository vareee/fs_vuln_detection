import random
from PoC import TranscriptInspector, H, ObjectCategory


p = 2**255 - 19
q = 2**127 - 1

def gexp(b, e):
    return pow(b, e % q, p)

def setup(m, n):
    return {
        "m": m,
        "n": n,
        "g_vec": [random.randint(0, q - 1) for _ in range(m * n)],
        "h_vec": [random.randint(0, q - 1) for _ in range(m * n)],
        "g": random.randint(0, q - 1),
        "h": random.randint(0, q - 1),
        "u": random.randint(0, q - 1),
    }

def delta(y, z, m, n):
    sum_y = 0
    y_exp = 1
    for _ in range(n):
        sum_y = (sum_y + y_exp) % q
        y_exp = (y_exp * y) % q

    sum_2 = (pow(2, n, q) - 1) % q
    sum_z = 0
    for j in range(1, m + 1):
        sum_z = (sum_z + pow(z, j + 2, q) * sum_2) % q

    return ((z - pow(z, 2, q)) * sum_y - sum_z) % q

def forge_bulletproof(params):
    transcript = TranscriptInspector()
    
    m = params['m']
    n = params['n']
    g_vec = params["g_vec"]
    h_vec = params["h_vec"]
    g = params['g']
    h = params['h']
    u = params['u']

    m_t = transcript.add(name="m", subject="prover", category=ObjectCategory.Pubkey, value=params['m'])
    n_t = transcript.add(name="n", subject="prover", category=ObjectCategory.Pubkey, value=params['n'])
    g_vec_t = transcript.add(name="g_vec", subject="prover", category=ObjectCategory.Pubkey, value=params["g_vec"])
    h_vec_t = transcript.add(name="h_vec", subject="prover", category=ObjectCategory.Pubkey, value=params["h_vec"])
    g_t = transcript.add(name="h", subject="prover", category=ObjectCategory.Generator, value=params['g'])
    h_t = transcript.add(name="h", subject="prover", category=ObjectCategory.Generator, value=params['h'])
    u_t = transcript.add(name="u", subject="prover", category=ObjectCategory.Generator, value=params['u'])

    a_L = [random.randint(0, 1) for _ in range(n)]
    a_R = [(a - 1) % q for a in a_L]
    s_L = [random.randint(0, q - 1) for _ in range(n)]
    s_R = [random.randint(0, q - 1) for _ in range(n)]
    alpha = random.randint(0, q - 1)
    ro   = random.randint(0, q - 1)

    a_L_t = transcript.add(name="a_L", subject="prover", category=ObjectCategory.Constant, value=[random.randint(0, 1) for _ in range(n)])
    a_R_t = transcript.add(name="a_R", subject="prover", category=ObjectCategory.Constant, value=[(a - 1) % q for a in a_L])
    s_L_t = transcript.add(name="s_L", subject="prover", category=ObjectCategory.Constant, value=[random.randint(0, q - 1) for _ in range(n)])
    s_R_t = transcript.add(name="s_R", subject="prover", category=ObjectCategory.Constant, value=[random.randint(0, q - 1) for _ in range(n)])
    alpha_t = transcript.add(name="alpha", subject="prover", category=ObjectCategory.Constant, value=random.randint(0, q - 1))
    ro_t = transcript.add(name="ro", subject="prover", category=ObjectCategory.Constant, value=random.randint(0, q - 1))

    A = gexp(h, alpha)
    S = gexp(h, ro)
    for i in range(n):
        A = (A * gexp(g_vec[i], a_L[i])) % p
        A = (A * gexp(h_vec[i], a_R[i])) % p
        S = (S * gexp(g_vec[i], s_L[i])) % p
        S = (S * gexp(h_vec[i], s_R[i])) % p

    A_t = transcript.add(name="A", subject="prover", category=ObjectCategory.Commitment, value=A)
    S_t = transcript.add(name="S", subject="prover", category=ObjectCategory.Commitment, value=S)

    data = b""
    for x in str(A_t.value):
        data += x.encode()
    for x in str(S_t.value):
        data += x.encode()
    
    y = H(data, q)
    z = H(data, q)
    y_t = transcript.record_challenge(challenge_name="y", used_names=["A", "S"], value=H(data, q))
    z_t = transcript.record_challenge(challenge_name="z", used_names=["A", "S"], value=H(data, q))

    t1 = random.randint(0, q - 1)
    t2 = random.randint(0, q - 1)
    tau1 = random.randint(0, q  -1)
    tau2 = random.randint(0, q  -1)
    T1 = (gexp(g, t1) * gexp(h, tau1)) % p
    T2 = (gexp(g, t2) * gexp(h, tau2)) % p

    t1_t = transcript.add(name="t1", subject="prover", category=ObjectCategory.Constant, value=t1)
    t2_t = transcript.add(name="t2", subject="prover", category=ObjectCategory.Constant, value=t2)
    tau1_t = transcript.add(name="tau1", subject="prover", category=ObjectCategory.Constant, value=tau1)
    tau2_t = transcript.add(name="tau2", subject="prover", category=ObjectCategory.Constant, value=tau2)
    T1_t = transcript.add(name="T2", subject="prover", category=ObjectCategory.Commitment, value=(gexp(g, t1) * gexp(h, tau1)) % p)
    T2_t = transcript.add(name="T2", subject="prover", category=ObjectCategory.Commitment, value=(gexp(g, t2) * gexp(h, tau2)) % p)

    for x in str(T1.value):
        data += x.encode()
    for x in str(T2.value):
        data += x.encode()
    
    x = H(data, q)
    x_t = transcript.record_challenge(challenge_name="x", used_names=["A", "S", "T1", "T2"], value=H(data, q))

    l = [((a_L[i] - z) + s_L[i] * x) % q for i in range(n)]
    r = [(gexp(y, i) * (a_R[i] + z + s_R[i] * x) + gexp(z, 2) * gexp(2, i)) % q for i in range(n)]
    t_hat = sum((l[i] * r[i]) % q for i in range(n)) % q
    
    l_t = transcript.add(name="l", subject="prover", category=ObjectCategory.Constant, value=l)
    r_t = transcript.add(name="r", subject="prover", category=ObjectCategory.Constant, value=r)
    t_hat_t = transcript.add(name="t_hat", subject="prover", category=ObjectCategory.Constant, value=t_hat)

    mu = (alpha + ro * x) % q
    tau_x = random.randint(0, q - 1)
    mu_t = transcript.add(name="mu", subject="prover", category=ObjectCategory.Constant, value=(alpha + ro * x) % q)
    tau_x_t = transcript.add(name="tau_x", subject="prover", category=ObjectCategory.Constant, value=tau_x)
    
    for x in str(t_hat):
        data += x.encode()
    for x in str(tau_x):
        data += x.encode()
    for x in str(mu):
        data += x.encode()
    
    w = H(data, q)
    w = transcript.record_challenge(challenge_name="w", used_names=["A", "S", "T1", "T2", "t_hat", "tau_x", "mu"], value=H(data, q))

    h_prime = [gexp(h_vec[i], pow(y, -m * n, q)) for i in range(m * n)]
    u_prime = gexp(u, w)
    P_prime = gexp(h, -mu)
    P_prime = (P_prime * A) % p
    P_prime = (P_prime * gexp(S, x)) % p
    for g_i in g_vec:
        P_prime = (P_prime * gexp(g_i, -z)) % p

    y_exp = 1
    for i in range(m * n):
        P_prime = (P_prime * gexp(h_prime[i], z * y_exp)) % p
        y_exp = (y_exp * y) % q

    for j in range(1, m + 1):
        z_exp = pow(z, j + 1, q)
        two_exp = 1
        for i in range(n):
            idx = (j - 1) * n + i
            P_prime = (P_prime * gexp(h_prime[idx], z_exp * two_exp)) % p
            two_exp = (two_exp * 2) % q

    P_prime = (P_prime * gexp(u_prime, t_hat)) % p
    pi_BP_IPA = {"t_hat": t_hat, "mu": mu}

    h_prime_t = transcript.add(name="h_prime", subject="prover", category=ObjectCategory.Constant, value=h_prime)
    u_prime_t = transcript.add(name="u_prime", subject="prover", category=ObjectCategory.Constant, value=u_prime)
    P_prime_t = transcript.add(name="P_prime", subject="prover", category=ObjectCategory.Constant, value=P_prime)
    pi_BP_IPA_t = transcript.add(name="pi_BP_IPA", subject="prover", category=ObjectCategory.Constant, value=pi_BP_IPA)

    rhs_v = (t_hat - t1*x - t2*x*x - delta(y, z, m, n)) % q
    rhs_g = (tau_x - tau1*x - tau2*x*x) % q

    V = []
    for j in range(1, m + 1):
        if j == 1:
            z_exp = pow(z, 2, q)
            vj = (rhs_v * pow(z_exp, -1, q)) % q
            gj = (rhs_g * pow(z_exp, -1, q)) % q
        else:
            vj = 0
            gj = 0

        Vj = (gexp(g, vj) * gexp(h, gj)) % p
        V.append(Vj)

    V_t = transcript.add(name="V", subject="prover", category=ObjectCategory.Constant, value=V)

    return {
        "V": V,
        "A": A,
        "S": S,
        "T1": T1,
        "T2": T2,
        "t_hat": t_hat,
        "tau_x": tau_x,
        "mu": mu,
        "PiBP-IPA": pi_BP_IPA
    }

try:
    params = setup(m=23, n=17)
    proof = forge_bulletproof(params)
except Exception as e:
    print("Detected: ", e)
