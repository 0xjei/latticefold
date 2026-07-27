#!/usr/bin/env python3
"""Generate test vectors for the 4-channel C7 final-decryption circuit
(ProdParams: 4x61-bit channels, Q ~ 2^244, t = 2^20), T=2 reconstruction
parties at evaluation points 1 and 2, degree N=16384.
"""
import random

Q0=0x1fffffffffe00001; Q1=0x1ffffffffe600001; Q2=0x1fffffffef600001; Q3=0x1fffffffed200001
QS=[Q0,Q1,Q2,Q3]
T_PLAIN=1<<20
Q=Q0*Q1*Q2*Q3
DELTA=(Q-1)//T_PLAIN
N=16384

def inv(a,m): return pow(a,m-2,m)

random.seed(7)
# Message and a small centered decode error per coefficient.
m=[random.randrange(T_PLAIN) for _ in range(N)]
e_signed=[random.randrange(-1000,1001) for _ in range(N)]
# u = Delta*m + e over the integers (|e| << Delta/2).
u=[DELTA*m[k]+e_signed[k] for k in range(N)]
assert all(0 <= x < Q for x in u)

# Per-channel residues and T=2 "decryption shares" d_1, d_2 with
# u_l = 2*d_1 - d_2 (mod q_l): pick d_2 at random, solve d_1.
u_l=[[x % q for x in u] for q in QS]
d_1_l=[]; d_2_l=[]
for l,q in enumerate(QS):
    d2=[random.randrange(q) for _ in range(N)]
    d1=[((u_l[l][k]+d2[k])*inv(2,q))%q for k in range(N)]
    d_1_l.append(d1); d_2_l.append(d2)

# Garner digits and quotient witnesses per coefficient.
r0s=[];t1s=[];t2s=[];t3s=[];s0s=[];s1s=[];s2s=[];s3s=[];es=[]
for k in range(N):
    r0=u_l[0][k]
    t1=(u_l[1][k]-r0)%Q1*inv(Q0%Q1,Q1)%Q1
    x01=r0+Q0*t1
    t2=(u_l[2][k]-x01%Q2)%Q2*inv((Q0*Q1)%Q2,Q2)%Q2
    x012=x01+Q0*Q1*t2
    t3=(u_l[3][k]-x012%Q3)%Q3*inv((Q0*Q1*Q2)%Q3,Q3)%Q3
    val=x012+Q0*Q1*Q2*t3
    assert val==u[k]
    r0s.append(r0);t1s.append(t1);t2s.append(t2);t3s.append(t3)
    s0s.append(t1+Q1*t2+Q1*Q2*t3)
    s1s.append((val-u_l[1][k])//Q1)
    s2s.append((val-u_l[2][k])//Q2)
    s3s.append((val-u_l[3][k])//Q3)
    es.append(e_signed[k]%Q)  # centered e as a residue mod Q

def fmt(v): return "["+", ".join(f'"{x}"' for x in v)+"]"
lines={
 "d_0_1":d_1_l[0], "d_0_2":d_2_l[0], "d_1_1":d_1_l[1], "d_1_2":d_2_l[1],
 "d_2_1":d_1_l[2], "d_2_2":d_2_l[2], "d_3_1":d_1_l[3], "d_3_2":d_2_l[3],
 "u_0":u_l[0], "u_1":u_l[1], "u_2":u_l[2], "u_3":u_l[3],
 "u":u, "m":m, "r0":r0s, "t1":t1s, "t2":t2s, "t3":t3s,
 "s0":s0s, "s1":s1s, "s2":s2s, "s3":s3s, "e":es,
}
with open("Prover.toml","w") as f:
    for name,arr in lines.items():
        f.write(f"{name} = {fmt(arr)}\n")
print("wrote Prover.toml (4 channels, N=16384)")
