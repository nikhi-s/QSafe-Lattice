"""
run_pqc_benchmark.py

Entry point for the Kyber / FrodoKEM benchmark suite with integrated
hardware CPU sanity checks and component ratio drift validation.
"""
import argparse
import os
import sys
import time

from pqc_config import (
    KYBER_TRIALS, FRODO_TRIALS,
    PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV,
)
from verify_pqc_results import preflight_check, verify_pqc_results


def run_cpu_sanity_check(threshold_seconds: float = 0.20) -> bool:
    """
    Executes a 1M loop compute check to verify host CPU performance
    before starting the benchmark suite. Healthy baseline is ~0.08s.
    """
    print("--- Running Host CPU Sanity Check ---")
    t0 = time.perf_counter()
    sum(i * i for i in range(1_000_000))  # 1 Million iterations (baseline ~0.08s)
    elapsed = time.perf_counter() - t0

    if elapsed > threshold_seconds:
        print(f"[FAIL (HOST THROTTLED)] Sanity compute check: {elapsed:.3f}s (Threshold: < {threshold_seconds:.2f}s)")
        print("-> Host VM is CPU-throttled. Disconnect and recreate the Colab runtime.")
        return False

    print(f"[PASS] Sanity compute check: {elapsed:.3f}s < {threshold_seconds:.2f}s (Clean Host VM)")
    return True


def check_session_drift(bench_results, ratio_min: float = 0.85, ratio_max: float = 1.15):
    """
    Validate component ratio alignment to catch hardware contention mid-run.

    Uses MEAN, not median, for this internal comparison specifically.
    Mean is additive (E[A+B+C] = E[A]+E[B]+E[C]), so exchange_mean should
    track sum(component_means) closely under normal conditions. Median is
    NOT additive -- median(A+B+C) != median(A)+median(B)+median(C) in
    general, especially for right-skewed timing distributions -- so using
    median here produced false "drift" failures purely from sampling
    noise (observed empirically: FrodoKEM's n=100 trials gave a stable
    0.63x ratio with no other sign of contention, while Kyber's n=500
    trials passed cleanly at ~1.0x -- consistent with a sample-size/
    additivity artifact, not real hardware contention).

    NOTE: this does not change the project's reporting convention -- all
    published figures/tables/text still use MEDIAN (see benchmark_pqc.py).
    This function only uses mean internally, for this one sanity check.
    """
    ck = bench_results["complete_key_exchange"]
    pv = bench_results["per_variant"]

    targets = ["Kyber768", "FrodoKEM-976-AES"]
    drift_detected = False
    print("\n--- Session Drift & In-Session Consistency Gate ---")

    for alg_name in targets:
        ex_time = ck[alg_name]["mean_time_s"]
        comp_time = sum(pv[alg_name][m]["mean"] for m in ["keygen_time_s", "encap_time_s", "decap_time_s"])
        ratio = ex_time / comp_time

        status = "PASS" if ratio_min <= ratio <= ratio_max else "FAIL (DRIFT DETECTED)"
        print(f"[{status}] {alg_name}: exchange/components = {ratio:.2f}x (Allowed target: {ratio_min}-{ratio_max}x)")

        if status.startswith("FAIL"):
            drift_detected = True

    if drift_detected:
        raise RuntimeError("Session validation failed due to hardware contention/drift. Aborting run.")

    print("All session consistency gates passed successfully!\n")


def print_environment():
    import platform
    import sys as _sys

    print("=" * 62)
    print("EXECUTION ENVIRONMENT")
    print("=" * 62)
    print(f"Platform:        {platform.platform()}")
    print(f"Processor:       {platform.processor() or 'n/a'}")
    print(f"Python:          {_sys.version.split()[0]}")

    try:
        import oqs
        print(f"liboqs:          {oqs.oqs_version()}")
        print(f"liboqs-python:   {oqs.oqs_python_version()}")
    except ImportError:
        print("liboqs:          NOT INSTALLED (--reuse-csv only)")
    print("=" * 62 + "\n")


def main(reuse_csv: bool = False):
    print_environment()
    preflight_check()

    if reuse_csv:
        from benchmark_pqc import load_results_from_csv
        results = load_results_from_csv(PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV)
    else:
        if not run_cpu_sanity_check(threshold_seconds=0.20):
            raise RuntimeError("CPU sanity check failed. Aborting pipeline before benchmarking.")

        for path in (PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV):
            if os.path.exists(path):
                os.remove(path)

        from benchmark_pqc import run_full_benchmark_suite
        results = run_full_benchmark_suite(num_trials=FRODO_TRIALS, kyber_num_trials=KYBER_TRIALS)

        # Enforce in-session consistency gate check
        check_session_drift(results)

    print("\n" + "=" * 62)
    print("VERIFICATION")
    print("=" * 62)
    verify_pqc_results(PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV)

    return results


if __name__ == "__main__":
    import matplotlib
    matplotlib.use("Agg")

    parser = argparse.ArgumentParser()
    parser.add_argument("--reuse-csv", action="store_true")
    args = parser.parse_args()

    main(reuse_csv=args.reuse_csv)
