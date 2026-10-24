from math import comb, log2, sqrt, log, pi
q=12289
comp=lambda x,d: ((x<<d)+q//2)//q & ((1<<d)-1)
decomp=lambda c,d: ((c&((1<<d)-1))*q+(1<<(d-1)))>>d
def cm(x):
    x%=q; return x-q if x>q//2 else x
def errdist(d):
    D={}
    for x in range(q):
        k=cm(decomp(comp(x,d),d)-x); D[k]=D.get(k,0)+1
    return D
eu,ev=errdist(11),errdist(5); var=lambda D: sum(k*k*c for k,c in D.items())/q
for name,w in [("MOS-128",192),("MOS-256",288)]:
    N=2*w*20+20; t=3072-w*max(map(abs,eu))-max(map(abs,ev))
    lb=log2(2*sum(comb(2*N,N+k) for k in range(t+1,N+1)))-2*N
    sig=sqrt(N/2+w*var(eu)); z=(3072-192)/sig
    print(name,"sigma_total=%.1f rigorous per-bit 2^%.0f per-ct 2^%.0f gaussian-approx per-bit 2^%.0f"%(sqrt(N/2+w*var(eu)+var(ev)),lb,lb+8,(-z*z/2-log(z*sqrt(2*pi)))/log(2)+1))
