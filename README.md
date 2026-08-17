# Q-Safe: Adaptive Post-Quantum Cryptography

Benchmarking code and reproducible data for **"Q-Safe: Mitigating Quantum Threats with
Lattice-Based Cryptography"** — a comparison of RSA, Kyber (ML-KEM), and FrodoKEM, and a
simulation of Q-Safe, an adaptive framework that selects between them at runtime based on
threat level and device constraints.

> **Status:** manuscript in preparation for the *Journal of Emerging Investigators*.
> Every number in the paper comes from the August 2026 runs recorded in this repository.

---

## Results at a glance

| | Finding |
|---|---|
| **RSA scaling** | Decryption rises from 0.131 ms (1024-bit) to 37.60 ms (8192-bit); key generation from 0.013 s to 6.74 s median, with a **26.3 s** worst case |
| **Kyber vs. FrodoKEM** | At matched NIST security level 3, a complete Kyber key exchange is **54.6× faster** (0.1250 ms vs. 6.8215 ms); FrodoKEM ciphertexts are 12.7–14.5× larger |
| **Q-Safe** | Cuts cumulative key-exchange time **43.8%** (rising-threat scenario) and **73.9%** (threat-spike scenario) versus an always-FrodoKEM deployment, with **zero overhead** on a constrained edge device |

---

## Reproducing the results

Two independent pipelines. Neither depends on the other's data.

### RSA — runs anywhere, no liboqs needed

```bash
pip install -r requirements.txt

python run_rsa_benchmark.py              # pre-flight -> benchmark -> verify -> rsa_benchmark_results.csv
python generate_rsa_table_and_figure.py  # Table 1 + Figure 2 (cross-checked against each other)
python plot_complexity_figure.py         # Figure 1 (analytic models -- needs no data at all)
```

The benchmark takes hours, dominated by RSA-8192 key generation (6.7 s median per key, up
to 26 s). To rebuild the outputs from the committed data instead of re-measuring:

```bash
python run_rsa_benchmark.py --reuse-csv  # verify the committed CSV, skip benchmarking
```

**Re-running the benchmark produces different timings** — cloud hardware varies from
session to session — so the published numbers come from one frozen run. `--reuse-csv` is
the way to reproduce the paper's figures; a fresh run measures *this* machine, not the one
in the paper.

`verify_rsa_results.py` runs automatically inside `run_rsa_benchmark.py` and can also be
run on its own to re-check the committed CSV at any time:

```bash
python verify_rsa_results.py             # OAEP limit table + all data assertions
```

Each script is independently runnable — `plot_complexity_figure.py` in particular needs no
benchmark data, so Figure 1 regenerates in about a second. To run the whole chain from a
notebook or the Python prompt:

```python
from run_rsa_benchmark import main
from generate_rsa_table_and_figure import generate_table_and_figure
from plot_complexity_figure import plot_complexity_figure

df = main(reuse_csv=True)                                # benchmark (or reuse) + verify
generate_table_and_figure("rsa_benchmark_results.csv")   # Table 1 + Figure 2
plot_complexity_figure()                                 # Figure 1
```

All figures are written to `figures/`, which the scripts create if it does not exist. Every
plotting function takes a `save_path` argument, so the destination can be changed without
editing the code.

### Kyber / FrodoKEM — needs liboqs

`pip install oqs` does **not** work: there is no prebuilt wheel, so liboqs has to be built
from source. In Google Colab:

```bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python && pip install . && cd ..
```

Then:

```python
from benchmark_pqc import run_full_benchmark_suite
from verify_pqc_results import verify_pqc_results
from plot_pqc_comparison import plot_figure4
from qsafe_simulation import extract_key_exchange_times, run_all_scenarios

results = run_full_benchmark_suite(num_trials=100, kyber_num_trials=500)
verify_pqc_results()
plot_figure4(results["per_variant"], stat="median", error_bar_type="sem")

k, f = extract_key_exchange_times(results["complete_key_exchange"], stat="median")
table2, _ = run_all_scenarios(k, f)      # Figures 4-5 + Table 2
```

The Q-Safe simulation uses a fixed random seed (42), so **Table 2 regenerates exactly**
from the committed CSVs on any machine — only the underlying timing inputs are
hardware-dependent.

---

## Benchmark environment (the runs reported in the paper)

Google Colab CPU runtime · Ubuntu 22.04.5 LTS · Intel Xeon @ 2.20 GHz (2 vCPU, x86_64) ·
Python 3.12.13

- **RSA:** `cryptography` 49.0.0 (OpenSSL backend), PKCS#1 v2 OAEP with SHA-256 and MGF1-SHA-256, 16-byte messages
- **KEM:** liboqs 0.16.0 / liboqs-python 0.16.1.dev0. This version ships the
  **ISO-standardized FrodoKEM with salted ciphertexts** (9752 / 15792 / 21696 bytes),
  which differ from pre-ISO builds (9720 / 15744 / 21632 bytes) — `verify_pqc_results.py`
  detects which variant is installed and reports it
- **Supporting libraries:** numpy 2.0.2 · pandas 2.2.2 · matplotlib 3.10.0
- **Reporting:** medians throughout, with standard error of the mean for uncertainty;
  500 trials for RSA-1024 and all Kyber variants, 100 trials for everything else;
  untimed warm-up calls discarded before measurement

---

## Files

**RSA pipeline**

| File | Role |
|---|---|
| `rsa_implementation.py` | Key generation, OAEP encrypt/decrypt, plaintext-limit helper |
| `run_config.py` | Run parameters — the single source of truth, read by the benchmark *and* the checks |
| `verify_rsa_results.py` | Pre-flight config validation + post-run data assertions |
| `benchmark_rsa.py` | Benchmark library: timing harness with checkpoint/resume, plotting helpers |
| `run_rsa_benchmark.py` | Entry point: pre-flight → benchmark → verify → `rsa_benchmark_results.csv` |
| `generate_rsa_table_and_figure.py` | Table 1 + Figure 2, with a built-in check that the two agree |
| `plot_complexity_figure.py` | Figure 1 — analytic GNFS/Shor and LWE/Grover complexity models |

**Kyber / FrodoKEM / Q-Safe**

| File | Role |
|---|---|
| `benchmark_pqc.py` | liboqs harness: per-operation and complete-key-exchange timing |
| `verify_pqc_results.py` | Trial counts, ciphertext-size constants, FrodoKEM variant detection |
| `plot_pqc_comparison.py` | Figure 3 — Kyber vs. FrodoKEM at matched security levels |
| `qsafe_simulation.py` | EMA threat smoothing, environment-derived weights, logistic suitability scoring, three runtime scenarios (Figures 4–5, Table 2) |
| `build_figure6_drawio.py` | Q-Safe architecture schematic (draw.io source) |

**Data** — `rsa_benchmark_results.csv` · `pqc_benchmark_results.csv` ·
`pqc_complete_key_exchange_results.csv` · `qsafe_simulation_summary.csv` · the generated
summary tables

**Figures** — `figures/` (created automatically; regenerated by the scripts above)

**Notebooks** — `RSA_Kyber_Benchmarking_Aug2026.ipynb` · `PQC_Lattice_August2026.ipynb`.
Each notebook writes its own `.py` modules with `%%writefile`, so the code that produced
the published results and the code in this repository are identical by construction.

---

## Notes on the methodology

A few decisions worth knowing about, all documented in the source:

- **Medians, not means.** Timing distributions are right-skewed — an OS interruption adds
  delay but never subtracts it — so the mean exceeds the median at every RSA key size.
  The paper reports medians with SEM.
- **Warm-up calls are discarded.** The first operation against a fresh key costs roughly
  2× a steady-state call, because OpenSSL builds its Montgomery and blinding context
  lazily. Left in, that artifact would attach itself to whichever measurement happened to
  run first.
- **RSA-1024 uses 500 trials, not 100.** Its encryption times are small enough that
  scheduler jitter dominates; the extra trials tighten the estimate.
- **Memory measurement was removed, not fixed.** `tracemalloc` reported ~24 bytes for RSA
  key generation regardless of key size, because the real allocation happens inside
  OpenSSL, outside Python's allocator. A process-RSS approach was also non-monotonic.
  Publishing a broken measurement seemed worse than publishing none.
- **The GNFS constant is `(64/9)^(1/3)` ≈ 1.923**, not `64/9`. The cube root belongs on
  the constant in `L_N[1/3, c]`; the earlier code inflated the exponent ~3.7×.
- **Q-Safe's suitability sub-scores use a bounded logistic transform** of the log time
  ratio rather than the raw ratio. With a raw ratio, Kyber's ~55× speed advantage would
  swamp the security dimension entirely and FrodoKEM could never be selected at any
  threat level.

---

## Citing

Swaminathan, N., and S. M. Rathinakumar. *Q-Safe: Mitigating Quantum Threats with
Lattice-Based Cryptography.* Manuscript in preparation.

## License

See `LICENSE`.
