# Core-SVP estimator (primal uSVP ADPS16 w/ secret rescaling, dual w/ sieve-vector reuse,
# drop-zeros guessing, primal hybrid with idealised MITM/Grover). Usage: python3 -I lwe_est.py
from math import *
CC,CQ=0.292,0.265
def delta(b): return ((pi*b)**(1.0/b)*b/(2*pi*e))**(1.0/(2*(b-1)))
def logbin(n,k): return -1e18 if k<0 or k>n else (lgamma(n+1)-lgamma(k+1)-lgamma(n-k+1))/log(2)
def primal_beta(n,m,q,se,ss):
    nu=se/ss; best=None
    for mm in range(50,m+1,4):
        d=mm+n+1; lv=mm*log2(q)+n*log2(nu)
        for b in range(50,d):
            if log2(se)+0.5*log2(b) <= (2*b-d-1)*log2(delta(b))+lv/d:
                if best is None or b<best[0]: best=(b,mm)
                break
    return best
def dual(n,m,q,se,ss,coef):
    nu=se/ss; best=(1e9,)
    for mm in range(50,m+1,8):
        d=mm+n; ld=n*log2(q)-n*log2(nu)
        for b in range(100,d,2):
            x=2**(d*log2(delta(b))+ld/d)*se/q; le=-2*pi*pi*x*x/log(2)
            c=coef*b+max(0.0,-2*le-0.2075*b)
            if c<best[0]: best=(c,b,mm)
    return best
def drop(n,m,q,se,h,coef,quantum):
    best=(1e9,)
    for k in range(0,n-h,8):
        b,_=primal_beta(n-k,m,q,se,sqrt(h/(n-k))); lp=logbin(n-h,k)-logbin(n,k)
        c=coef*b-(lp/2 if quantum else lp)
        if c<best[0]: best=(c,k,b)
    return best
def ladd(a,b):
    if a<b: a,b=b,a
    return a if b<-1e17 else a+log2(1+2**(b-a))
def hybrid(n,m,q,se,h,coef,kstep=16):
    best=(1e9,); tot=logbin(n,h); nu=se/sqrt(h/n)
    for k in range(0,n-h,kstep):
        nn=n-k; lpw=[]; lS=[]; acc=-1e18; S=-1e18
        for j in range(0,min(k,h)+1):
            acc=ladd(acc,logbin(k,j)+logbin(n-k,h-j)-tot); S=ladd(S,logbin(k,j)+j)
            lpw.append(min(0.0,acc)); lS.append(S)
        for mm in range(256,m+1,64):
            d=mm+nn+1; lv=mm*log2(q)+nn*log2(nu)
            for b in range(100,min(d,1300),8):
                dl=log2(delta(b)); lb1=d*dl+lv/d; lpb=0.0
                for i in range(d):
                    v=erf(2**(lb1-2*i*dl)*sqrt(pi)/(2*se*sqrt(2*pi)))
                    if v<=1e-300: lpb=-1e9; break
                    lpb+=log2(v)
                    if lpb<-60: break
                if lpb<-60: continue
                for hk in range(len(lpw)):
                    s=lS[hk]/2+2*log2(d); t=max(coef*b,s)+1-lpw[hk]-lpb
                    if t<best[0]: best=(t,k,mm,b,hk)
                    if s>coef*b+60: break
    return best
if __name__=='__main__':
    q=12289
    for name,n,se,h in [("MOS-128 key",768,sqrt(10),192),("MOS-128 ct",768,sqrt(13.17),192),("MOS-256 key",1152,sqrt(10),288),("MOS-256 ct",1152,sqrt(13.17),288)]:
        ss=sqrt(h/n); b,mm=primal_beta(n,n,q,se,ss)
        print(name,"primal b=%d: %.1f/%.1f"%(b,CC*b,CQ*b),"dual %.1f/%.1f"%(dual(n,n,q,se,ss,CC)[0],dual(n,n,q,se,ss,CQ)[0]),
              "drop %.1f/%.1f"%(drop(n,n,q,se,h,CC,False)[0],drop(n,n,q,se,h,CQ,True)[0]),
              "hybrid %.1f/%.1f"%(hybrid(n,n,q,se,h,CC,32)[0],hybrid(n,n,q,se,h,CQ,32)[0]),flush=True)
