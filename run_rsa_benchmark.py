
"""
run_rsa_benchmark.py
 
Entry point for the RSA benchmark: validates the run configuration, runs the
benchmark, writes rsa_benchmark_results.csv, and verifies it.
 
    python run_rsa_benchmark.py                 # full run (hours)
    python run_rsa_benchmark.py --reuse-csv     # skip benchmarking, verify the
                                                # existing CSV and rebuild outputs
 
Kept separate from benchmark_rsa.py so that module stays a pure library, with
no dependency on any particular run's configuration.
"""
 
import os
import sys, cryptography, numpy, pandas, matplotlib, platform
 
import pandas as pd
 
from benchmark_rsa import collect_benchmark_data, plot_line_charts
from run_config import KEY_SIZES, MESSAGE_SIZES, KEY_SIZE_SAMPLES
from verify_rsa_results import preflight_check, verify_results
 
RESULTS_CSV = "rsa_benchmark_results.csv"
 
 
def main(reuse_csv: bool = False, show_invariance_check: bool = False):
    """
    reuse_csv: skip benchmarking and verify/reuse an existing RESULTS_CSV.
        Use this to regenerate downstream outputs from an already-completed
        run WITHOUT re-benchmarking -- re-running would produce different
        timings and invalidate the manuscript's frozen numbers. The default
        (False) performs the real benchmark.
    """
    # Fails in seconds if the configuration is wrong, rather than hours in.
    preflight_check()
 
    if reuse_csv:
        if not os.path.exists(RESULTS_CSV):
            raise SystemExit(f"--reuse-csv given but {RESULTS_CSV} does not exist; "
                             f"run without the flag to benchmark from scratch.")
        print(f"[reuse] Skipping benchmark; using existing {RESULTS_CSV}")
        df = pd.read_csv(RESULTS_CSV)
    else:
        # Remove any stale CSV so a half-finished run cannot leave a file that
        # downstream verification would happily bless.
        if os.path.exists(RESULTS_CSV):
            os.remove(RESULTS_CSV)
            print(f"[fresh run] Removed stale {RESULTS_CSV}")
 
        df = collect_benchmark_data(
            KEY_SIZES, MESSAGE_SIZES,
            num_samples=10,
            key_size_samples=KEY_SIZE_SAMPLES,
            resume=False,
        )
        df.to_csv(RESULTS_CSV, index=False)
        print(f"Saved {len(df)} rows to {RESULTS_CSV} "
              f"({df['skipped_reason'].notna().sum()} skipped combinations)")
 
    # Verify before anything downstream consumes the data.
    verify_results(RESULTS_CSV)
 
    if show_invariance_check:
        # Diagnostic only, not a manuscript figure: flat lines confirm the
        # Methods claim that RSA-OAEP timing does not depend on message size.
        # Writes encryption_time_line_chart.png (filename comes from the metric,
        # not the title) -- inspect it, but there is no need to commit it.
        plot_line_charts(df, KEY_SIZES, "encryption_time", "invariance check")
        print("\nWrote encryption_time_line_chart.png (diagnostic only — not a manuscript figure).")

    print("\nNext steps:")
    print("  python generate_rsa_table_and_figure.py   ->  Table 1 + Figure 2")
    print("  python plot_complexity_figure.py          ->  Figure 1")

    return df
 
if __name__ == "__main__":
    # Force a non-interactive backend when run as a script, so an interactive
    # backend can never block the run waiting for a window to be closed. This
    # fires only under `python run_rsa_benchmark.py`; importing main() into a
    # notebook leaves the inline backend untouched.
    import matplotlib
    matplotlib.use("Agg")
 
    main(reuse_csv="--reuse-csv" in sys.argv, show_invariance_check=True)

    print("Python:", sys.version)
    print("Platform:", platform.platform())
    for m in (cryptography, numpy, pandas, matplotlib):
      print(m.__name__, m.__version__)
 
