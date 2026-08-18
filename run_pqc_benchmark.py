"""
run_pqc_benchmark.py

Entry point for the Kyber / FrodoKEM benchmark -- the KEM counterpart of
run_rsa_benchmark.py. One command, in the order the checks are actually
useful:

    environment -> pre-flight -> benchmark -> verify -> two CSVs

Usage:

    python run_pqc_benchmark.py               # measure (needs liboqs)
    python run_pqc_benchmark.py --reuse-csv   # verify committed CSVs, no measuring

WHY --reuse-csv MATTERS. Re-running the benchmark produces different
timings: Colab hardware and contention vary session to session. Every
number in the manuscript -- the 54.6x ratio, Table 2, Figures 3-5 --
comes from one frozen run. Use --reuse-csv to rebuild figures from that
run; a fresh run measures whatever machine you are on today, and then
every downstream artifact has to be regenerated and every quoted number
re-checked. Same discipline as the RSA side.

--reuse-csv also works without liboqs installed, so figures can be
regenerated on any laptop.
"""
import argparse
import os
import sys

from pqc_config import (
    KYBER_TRIALS, FRODO_TRIALS,
    PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV,
)
from verify_pqc_results import preflight_check, verify_pqc_results


def print_environment():
    """
    Print everything the Methods section has to state about the machine
    and the library stack. Imports are local so this function is
    self-contained and can be called from a notebook without the caller
    having imported anything first.
    """
    import platform
    import sys as _sys

    print("=" * 62)
    print("EXECUTION ENVIRONMENT (record this in Methods)")
    print("=" * 62)
    print(f"Platform:        {platform.platform()}")
    print(f"Processor:       {platform.processor() or 'n/a'}")
    print(f"Python:          {_sys.version.split()[0]}")

    for mod_name in ("numpy", "pandas", "matplotlib"):
        try:
            mod = __import__(mod_name)
            print(f"{mod_name + ':':17}{mod.__version__}")
        except ImportError:
            print(f"{mod_name + ':':17}not installed")

    # liboqs is the one that actually determines the ciphertext sizes, so
    # it gets reported whether or not it is present.
    try:
        import oqs
        print(f"liboqs:          {oqs.oqs_version()}")
        print(f"liboqs-python:   {oqs.oqs_python_version()}")
    except ImportError:
        print("liboqs:          NOT INSTALLED (--reuse-csv only)")
    print("=" * 62 + "\n")


def main(reuse_csv: bool = False):
    """
    Full KEM pipeline. Returns the nested results dict that
    plot_pqc_comparison and qsafe_simulation consume, so the notebook can
    hold on to it instead of re-reading the CSVs.

    NOTE: in --reuse-csv mode the returned dict has no "environment" key
    (it is reconstructed from the CSVs, which do not carry library
    versions). Nothing downstream reads it; print_environment() above
    covers the Methods text.
    """
    print_environment()
    preflight_check()

    if reuse_csv:
        missing = [p for p in (PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV)
                   if not os.path.exists(p)]
        if missing:
            print(f"ERROR: --reuse-csv given but these files are missing: {missing}")
            print("Run without --reuse-csv to measure them, or restore them from git.")
            sys.exit(1)
        print(f"Reusing committed data ({PER_VARIANT_CSV}, {COMPLETE_EXCHANGE_CSV}) "
              f"-- no benchmarking.\n")
        from benchmark_pqc import load_results_from_csv
        results = load_results_from_csv(PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV)
    else:
        # Remove stale CSVs first. Otherwise a run that dies partway
        # leaves a file that looks complete but mixes two sessions'
        # timings -- and the row-count assertion would be the only thing
        # standing between that and the manuscript.
        for path in (PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV):
            if os.path.exists(path):
                print(f"Removing stale {path}")
                os.remove(path)

        from benchmark_pqc import run_full_benchmark_suite
        print(f"Benchmarking: {KYBER_TRIALS} trials per Kyber variant, "
              f"{FRODO_TRIALS} per FrodoKEM variant.\n")
        results = run_full_benchmark_suite(num_trials=FRODO_TRIALS,
                                           kyber_num_trials=KYBER_TRIALS)

    print("\n" + "=" * 62)
    print("VERIFICATION")
    print("=" * 62)
    verify_pqc_results(PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV)

    print("\nNext:")
    print("  python generate_pqc_figure3.py     # Figure 3 (Kyber vs FrodoKEM)")
    print("  python run_qsafe_simulation.py     # Figures 4-5 + Table 2")
    return results


if __name__ == "__main__":
    # Non-interactive backend when run as a script, so an interactive
    # backend can never block waiting for a window to close. Fires only
    # under `python run_pqc_benchmark.py`; importing main() into a
    # notebook leaves the inline backend untouched.
    import matplotlib
    matplotlib.use("Agg")

    parser = argparse.ArgumentParser(
        description="Benchmark Kyber and FrodoKEM, then verify the results.")
    parser.add_argument("--reuse-csv", action="store_true",
                        help="Skip benchmarking; verify the committed CSVs instead. "
                             "Use this to reproduce the paper's figures.")
    args = parser.parse_args()

    main(reuse_csv=args.reuse_csv)
