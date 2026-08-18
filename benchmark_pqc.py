"""
benchmark_pqc.py

Kyber and FrodoKEM benchmarking via liboqs-python.

SETUP (run this in a Colab cell BEFORE running this script -- `pip install
oqs` on its own does NOT work, because there is no prebuilt wheel; the
`oqs` Python bindings require building the liboqs C library from source):

    !git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
    %cd liboqs-python
    !pip install .
    %cd ..

This clones the liboqs-python repo (which bundles a copy of the liboqs C
library), builds it via CMake, and installs the Python bindings. It takes
a few minutes the first time. Colab already has the build tools (cmake,
ninja, a C compiler) preinstalled; if you're running this somewhere else
and the `pip install .` step fails with a missing-cmake/ninja error, run:

    !apt-get install -y cmake ninja-build

first, then retry the liboqs-python install.

Run this in Google Colab (or any environment with liboqs-python installed
per the above). It requires network access to install liboqs, so it will
NOT run in this sandbox -- copy it into Colab, run the setup cell above
first, then run this script in a separate cell (or `python benchmark_pqc.py`
in a `!` shell cell) in the same session.

Fixes applied relative to the original RSA_Kyber_Benchmarking.ipynb:

1. ORIGINAL BUG: `benchmark_pqc()` took exactly ONE time.time() sample per
   (algorithm, message_length) pair. The paper's Methods section claims
   "100 trials were conducted, and the average values were used" -- that
   was never actually true for this function. Fixed: now averages
   `num_trials` (default 100) runs per algorithm, using time.perf_counter()
   for better sub-millisecond resolution, and reports both mean and median
   (median is more robust to occasional OS scheduling spikes).

2. ORIGINAL BUG: the `message_lengths = [1024, 2048, 4096]` loop is
   meaningless for KEM operations. `encap_secret()`/`decap_secret()` don't
   take a message as input at all -- KEM output size and timing depend
   only on the algorithm/security level, not on a "message length." The
   original code silently looped over the same operation 3x, adding noise
   without adding information. Fixed: removed. If you want three data
   points per algorithm for a chart, that's what the three separate
   Kyber/FrodoKEM security-level variants already give you.

3. ORIGINAL GAP: no code ever printed/saved the actual liboqs version used,
   even though your Methods text has a literal placeholder
   "[liboqs version and KEM identifier as printed by the benchmark
   notebook]". Fixed: version and mechanism list are captured into the
   results dict and printed, ready to paste into Methods.

4. NEW: added `benchmark_complete_key_exchange()`, which measures
   keygen + encapsulation + decapsulation as a single combined operation,
   median of 100 trials, for Kyber768 and FrodoKEM-976-AES specifically
   (NIST security level 3). This is the number your Q-Safe cost model and
   the per-exchange comparison reported in Table 2 of the manuscript --
   it did not previously exist as a standalone, clearly-scoped function.
"""

import time
import statistics
import platform

import pandas as pd

# liboqs is only needed to MEASURE. load_results_from_csv() rebuilds the
# same result structure from the committed CSVs, and every plotting and
# simulation script downstream works from that -- so importing this
# module must not hard-fail on a machine that never built liboqs.
# Without this guard, `run_pqc_benchmark.py --reuse-csv` (whose entire
# purpose is to regenerate figures without re-measuring) could not run
# outside Colab.
try:
    import oqs
except ImportError:
    oqs = None

from pqc_config import (
    KYBER_ALGS, FRODO_ALGS, LEVEL3_KYBER, LEVEL3_FRODO,
    KYBER_TRIALS, FRODO_TRIALS, NUM_WARMUP, MESSAGE_LENGTH_BYTES,
    PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV,
)


def _require_oqs():
    """Fail with an actionable message, not a bare NameError, when a
    measuring function is called without liboqs installed."""
    if oqs is None:
        raise ImportError(
            "liboqs-python is not installed, so nothing can be measured.\n"
            "  Install:  git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python\n"
            "            cd liboqs-python && pip install . && cd ..\n"
            "  Or, to work from the committed data instead of measuring:\n"
            "            python run_pqc_benchmark.py --reuse-csv"
        )


def get_environment_info():
    """Capture the exact liboqs version and platform for the Methods section."""
    _require_oqs()
    info = {
        "liboqs_version": oqs.oqs_version(),
        "liboqs_python_version": oqs.oqs_python_version(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "supported_kem_mechanisms": oqs.get_supported_kem_mechanisms(),
    }
    print("liboqs version:", info["liboqs_version"])
    print("liboqs-python version:", info["liboqs_python_version"])
    print("Python version:", info["python_version"])
    print("Platform:", info["platform"])
    return info


def benchmark_kem(kem_alg: str, num_trials: int = FRODO_TRIALS,
                   message_length: int = MESSAGE_LENGTH_BYTES,
                   num_warmup: int = NUM_WARMUP):
    """
    Benchmark key generation, encapsulation, and decapsulation for a single
    KEM algorithm, averaged over num_trials independent runs.

    `num_warmup` untimed trials are run first and discarded. This avoids
    contaminating the timed samples with one-time costs (first-call
    interpreter/library warm-up, cold caches) that don't reflect steady-
    state performance -- this matters more for fast operations (Kyber, at
    tens of microseconds) than slow ones, since a fixed warm-up cost is a
    much larger fraction of a small measurement.

    `message_length` is accepted only for logging/consistency with the RSA
    benchmark script's parameterization -- it has NO effect on timing or
    output size for a KEM, since encap_secret()/decap_secret() do not take
    a plaintext message. It is recorded in the result dict for traceability
    but should not be looped over as an independent variable.

    Returns a dict with:
      - mean/median/min/stdev/sem summaries per metric (as before, for
        direct compatibility with plot_pqc_comparison.py)
      - "raw" sub-dict with the individual per-trial timing lists
        (keygen_time_s, encap_time_s, decap_time_s), so results can be
        saved to a tidy CSV and re-aggregated later with any stat,
        exactly like benchmark_rsa.py's per-sample rows. This also means
        the raw data can be independently re-checked later (e.g. for the
        same kind of contention/bimodal timing issues found in the RSA
        benchmarks) without re-running the benchmark.

    NOTE ON INTERPRETING RESULTS: for very fast operations (Kyber's ~tens
    of microseconds), OS scheduling jitter and Python-level overhead can
    dominate the measurement, especially on a shared/virtualized
    environment like Colab. If the mean/median for adjacent security
    levels (e.g. Kyber768 vs Kyber1024) look nearly identical with large
    overlapping error bars, that is often a real noise-floor effect, not
    a bug. The `min` across trials is a diagnostic worth glancing at in
    that situation (system interference only ever adds delay, never
    subtracts it -- the principle behind Python's `timeit` reporting the
    minimum), but THIS PROJECT'S REPORTING CONVENTION IS MEDIAN
    throughout -- for the manuscript, all figures/tables, and the Q-Safe
    simulation inputs -- chosen for robustness to the transient
    contention measured on Colab and for consistency with the RSA
    benchmarks. Don't switch any single artifact to min/mean without
    switching all of them and the Methods text together.
    """
    keygen_times = []
    encap_times = []
    decap_times = []
    ciphertext_size = None

    kem = oqs.KeyEncapsulation(kem_alg)

    for _ in range(num_warmup):
        public_key = kem.generate_keypair()
        ciphertext, _ = kem.encap_secret(public_key)
        kem.decap_secret(ciphertext)

    for _ in range(num_trials):
        start = time.perf_counter()
        public_key = kem.generate_keypair()
        keygen_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        encap_times.append(time.perf_counter() - start)
        ciphertext_size = len(ciphertext)

        start = time.perf_counter()
        recovered_secret = kem.decap_secret(ciphertext)
        decap_times.append(time.perf_counter() - start)

        assert shared_secret == recovered_secret, f"Shared secret mismatch for {kem_alg}!"

    def summarize(samples):
        n = len(samples)
        stdev = statistics.stdev(samples) if n > 1 else 0.0
        return {
            "mean": statistics.mean(samples),
            "median": statistics.median(samples),
            "min": min(samples),
            "stdev": stdev,
            "sem": stdev / (n ** 0.5) if n > 1 else 0.0,
        }

    return {
        "algorithm": kem_alg,
        "message_length_note": message_length,  # recorded, not varied
        "num_trials": num_trials,
        "keygen_time_s": summarize(keygen_times),
        "encap_time_s": summarize(encap_times),
        "decap_time_s": summarize(decap_times),
        "ciphertext_size_bytes": ciphertext_size,
        "raw": {
            "keygen_time_s": keygen_times,
            "encap_time_s": encap_times,
            "decap_time_s": decap_times,
        },
    }


def benchmark_complete_key_exchange(kem_alg: str, num_trials: int = FRODO_TRIALS,
                                    num_warmup: int = NUM_WARMUP):
    """
    Measure a COMPLETE key exchange (keygen + encapsulation + decapsulation)
    as a single combined timed operation, per trial. This is the quantity
    the Q-Safe cost model in the paper actually uses (the per-exchange medians reported in Table 2 of the manuscript).

    Returns mean/median/min/stdev/sem in seconds, plus a "raw" list of the
    individual per-trial total times -- see benchmark_kem()'s docstring
    for why raw per-trial data is saved rather than only summaries.
    """
    kem = oqs.KeyEncapsulation(kem_alg)

    for _ in range(num_warmup):
        public_key = kem.generate_keypair()
        ciphertext, _ = kem.encap_secret(public_key)
        kem.decap_secret(ciphertext)

    total_times = []
    for _ in range(num_trials):
        start = time.perf_counter()
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        recovered_secret = kem.decap_secret(ciphertext)
        total_times.append(time.perf_counter() - start)
        assert shared_secret == recovered_secret

    n = len(total_times)
    stdev = statistics.stdev(total_times) if n > 1 else 0.0
    return {
        "algorithm": kem_alg,
        "num_trials": num_trials,
        "mean_time_s": statistics.mean(total_times),
        "median_time_s": statistics.median(total_times),
        "min_time_s": min(total_times),
        "stdev_time_s": stdev,
        "sem_time_s": stdev / (n ** 0.5) if n > 1 else 0.0,
        "raw": {"total_time_s": total_times},
    }


def save_results_to_csv(results: dict, per_variant_csv: str = PER_VARIANT_CSV,
                          complete_exchange_csv: str = COMPLETE_EXCHANGE_CSV):
    """
    Flatten run_full_benchmark_suite()'s raw per-trial data into two tidy
    CSVs, matching the pattern already used for RSA (rsa_benchmark_results.csv):
    one row per trial, aggregate later with pandas groupby + whatever stat
    you want, rather than locking in mean/median/min at benchmark time.

    This decouples the (expensive, network-dependent, liboqs-only-runs-in-
    Colab) benchmarking step from the (fast, portable) analysis/plotting
    step -- once you have these CSVs, plotting and table generation can
    happen anywhere pandas/matplotlib are available, no liboqs required,
    and the raw data can be independently re-checked later (e.g. for the
    same kind of contention/bimodal timing issues found in the RSA
    benchmarks) without re-running the benchmark.

    per_variant_csv columns: algorithm, trial_idx, keygen_time_s,
    encap_time_s, decap_time_s, ciphertext_size_bytes

    complete_exchange_csv columns: algorithm, trial_idx, total_time_s
    """
    per_variant_rows = []
    for alg, data in results["per_variant"].items():
        raw = data["raw"]
        n = data["num_trials"]
        for i in range(n):
            per_variant_rows.append({
                "algorithm": alg,
                "trial_idx": i,
                "keygen_time_s": raw["keygen_time_s"][i],
                "encap_time_s": raw["encap_time_s"][i],
                "decap_time_s": raw["decap_time_s"][i],
                "ciphertext_size_bytes": data["ciphertext_size_bytes"],
            })
    per_variant_df = pd.DataFrame(per_variant_rows)
    per_variant_df.to_csv(per_variant_csv, index=False)
    print(f"Saved {len(per_variant_df)} rows to {per_variant_csv}")

    complete_rows = []
    for alg, data in results["complete_key_exchange"].items():
        raw = data["raw"]
        n = data["num_trials"]
        for i in range(n):
            complete_rows.append({
                "algorithm": alg,
                "trial_idx": i,
                "total_time_s": raw["total_time_s"][i],
            })
    complete_df = pd.DataFrame(complete_rows)
    complete_df.to_csv(complete_exchange_csv, index=False)
    print(f"Saved {len(complete_df)} rows to {complete_exchange_csv}")

    return per_variant_df, complete_df


def load_results_from_csv(per_variant_csv: str = PER_VARIANT_CSV,
                            complete_exchange_csv: str = COMPLETE_EXCHANGE_CSV):
    """
    Reconstruct the same nested dict structure run_full_benchmark_suite()
    returns (mean/median/min/stdev/sem per metric, plus "raw" per-trial
    lists) by reading back the tidy CSVs saved by save_results_to_csv().

    This means plot_pqc_comparison.py's plot_figure4()/plot_all_comparisons()
    work completely unchanged whether fed a live benchmark run or data
    loaded from disk -- e.g.:

        results = load_results_from_csv()
        plot_figure4(results["per_variant"], stat="median", error_bar_type="sem")

    No liboqs/Colab required for this half of the workflow.
    """
    def summarize(samples):
        n = len(samples)
        stdev = statistics.stdev(samples) if n > 1 else 0.0
        return {
            "mean": statistics.mean(samples),
            "median": statistics.median(samples),
            "min": min(samples),
            "stdev": stdev,
            "sem": stdev / (n ** 0.5) if n > 1 else 0.0,
        }

    per_variant_df = pd.read_csv(per_variant_csv)
    per_variant_results = {}
    for alg, group in per_variant_df.groupby("algorithm"):
        per_variant_results[alg] = {
            "algorithm": alg,
            "num_trials": len(group),
            "keygen_time_s": summarize(group["keygen_time_s"].tolist()),
            "encap_time_s": summarize(group["encap_time_s"].tolist()),
            "decap_time_s": summarize(group["decap_time_s"].tolist()),
            "ciphertext_size_bytes": group["ciphertext_size_bytes"].iloc[0],
            "raw": {
                "keygen_time_s": group["keygen_time_s"].tolist(),
                "encap_time_s": group["encap_time_s"].tolist(),
                "decap_time_s": group["decap_time_s"].tolist(),
            },
        }

    complete_df = pd.read_csv(complete_exchange_csv)
    complete_key_exchange_results = {}
    for alg, group in complete_df.groupby("algorithm"):
        times = group["total_time_s"].tolist()
        n = len(times)
        stdev = statistics.stdev(times) if n > 1 else 0.0
        complete_key_exchange_results[alg] = {
            "algorithm": alg,
            "num_trials": n,
            "mean_time_s": statistics.mean(times),
            "median_time_s": statistics.median(times),
            "min_time_s": min(times),
            "stdev_time_s": stdev,
            "sem_time_s": stdev / (n ** 0.5) if n > 1 else 0.0,
            "raw": {"total_time_s": times},
        }

    return {
        "per_variant": per_variant_results,
        "complete_key_exchange": complete_key_exchange_results,
    }


def run_full_benchmark_suite(num_trials: int = FRODO_TRIALS,
                               kyber_num_trials: int = KYBER_TRIALS,
                               save_csv: bool = True):
    """
    Runs the full Kyber vs. FrodoKEM benchmark suite matching the paper's
    reported metrics: per-variant keygen/encap/decap/ciphertext-size, and
    the NIST-level-3 complete-key-exchange comparison used by Q-Safe.

    `kyber_num_trials`: if set, overrides num_trials for Kyber specifically.
    Kyber operations run in the tens-of-microseconds range, where OS
    scheduling jitter is a larger fraction of the signal than for
    FrodoKEM's millisecond-scale operations -- more trials (e.g. 500-1000)
    tighten Kyber's confidence interval without materially increasing
    total runtime, since each trial is still very fast. Defaults to
    num_trials if not set.
    """
    _require_oqs()
    env_info = get_environment_info()

    # Algorithm sets and trial counts come from pqc_config.py -- the same
    # module verify_pqc_results.py checks against, so the assertions can
    # never drift from what actually ran.
    kyber_algs = KYBER_ALGS
    frodo_algs = FRODO_ALGS
    kyber_trials = kyber_num_trials if kyber_num_trials is not None else num_trials

    per_variant_results = {}
    for alg in kyber_algs:
        print(f"Benchmarking {alg} ({kyber_trials} trials)...")
        per_variant_results[alg] = benchmark_kem(alg, num_trials=kyber_trials)
    for alg in frodo_algs:
        print(f"Benchmarking {alg} ({num_trials} trials)...")
        per_variant_results[alg] = benchmark_kem(alg, num_trials=num_trials)

    print("\nBenchmarking complete key exchange at NIST security level 3...")
    complete_exchange_results = {
        LEVEL3_KYBER: benchmark_complete_key_exchange(LEVEL3_KYBER, num_trials=kyber_trials),
        LEVEL3_FRODO: benchmark_complete_key_exchange(LEVEL3_FRODO, num_trials=num_trials),
    }

    kyber_min_ms = complete_exchange_results[LEVEL3_KYBER]["min_time_s"] * 1000
    frodo_min_ms = complete_exchange_results[LEVEL3_FRODO]["min_time_s"] * 1000
    kyber_med_ms = complete_exchange_results[LEVEL3_KYBER]["median_time_s"] * 1000
    frodo_med_ms = complete_exchange_results[LEVEL3_FRODO]["median_time_s"] * 1000
    print(f"\nComplete key exchange:")
    print(f"  Kyber768:         median={kyber_med_ms:.4f} ms, min={kyber_min_ms:.4f} ms "
          f"(n={kyber_trials})")
    print(f"  FrodoKEM-976-AES: median={frodo_med_ms:.4f} ms, min={frodo_min_ms:.4f} ms "
          f"(n={num_trials})")
    print(f"  Ratio (Frodo/Kyber), using median: {frodo_med_ms / kyber_med_ms:.1f}x")
    print(f"  Ratio (Frodo/Kyber), using min:    {frodo_min_ms / kyber_min_ms:.1f}x")
    print("  NOTE: this project reports MEDIAN values throughout (robust to the")
    print("  transient contention measured on shared Colab hardware, and consistent")
    print("  with the RSA benchmarks and the manuscript's Methods text). The min is")
    print("  printed above for reference only -- do not mix statistics between")
    print("  artifacts; see extract_key_exchange_times() in qsafe_simulation.py.")

    results = {
        "environment": env_info,
        "per_variant": per_variant_results,
        "complete_key_exchange": complete_exchange_results,
    }

    if save_csv:
        save_results_to_csv(results)

    return results
