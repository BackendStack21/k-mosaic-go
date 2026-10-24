# SLSS security estimates

These scripts reproduce the figures quoted for the SLSS (unstructured LWE)
component in `README.md` and `SECURITY_ASSESSMENT.md` §6.1. They were
written for the 2.0.0-dev.4 validation pass and are **not** the Lattice Estimator;
treat the results as a sanity check with an uncertainty of about ±10 bits.

- `lwe_est.py`: core-SVP cost (0.292·β classical, 0.265·β quantum) of the
  primal uSVP attack with secret rescaling, the dual attack, guessing zero
  positions of the sparse secret ("drop"), and a Howgrave-Graham hybrid with
  an idealised meet-in-the-middle (no memory cost; Grover quantumly). The
  same code gives 118.6 / 182.2 / 255.2 classical for ML-KEM-512/768/1024
  against the published 118 / 182 / 256. Runtime about three minutes.
- `dfr.py`: exact decryption-failure bound for the SLSS component from the
  centered-binomial noise and the compression rounding errors.

```sh
python3 -I lwe_est.py
python3 -I dfr.py
```

Expected output (classical/quantum log2 costs; "drop" and "hybrid" exploit
the sparse ternary secret, the hybrid deliberately favouring the attacker):

```text
MOS-128 key primal b=551: 160.9/146.0 dual 160.0/145.2 drop 160.9/145.8 hybrid 160.0/151.6
MOS-128 ct  primal b=560: 163.5/148.4 dual 162.6/147.6 drop 163.5/148.2 hybrid 161.8/154.0
MOS-256 key primal b=888: 259.3/235.3 dual 257.5/233.7 drop 259.3/234.7 hybrid 251.2/240.3
MOS-256 ct  primal b=901: 263.1/238.8 dual 261.6/237.4 drop 263.1/238.2 hybrid 255.2/243.3

MOS-128 sigma_total=129.4 rigorous per-bit 2^-1016 per-ct 2^-1008 gaussian-approx per-bit 2^-1348
MOS-256 sigma_total=137.7 rigorous per-bit 2^-516 per-ct 2^-508 gaussian-approx per-bit 2^-901
```

Newer dual attacks (MATZOV-style) are not modelled; they lower ML-KEM's
estimates by a similar amount.
