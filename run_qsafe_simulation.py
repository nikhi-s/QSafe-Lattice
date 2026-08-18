"""
run_qsafe_simulation.py

Figures 4-5 and Table 2 -- the Q-Safe adaptive-selection simulation.

    python run_qsafe_simulation.py

Reads the committed complete-key-exchange CSV, pulls the two median
per-exchange times out of it programmatically, and runs all three
scenarios. No timing number is ever typed by hand: the simulation's
inputs come from the same file the Results text quotes, so Table 2 and
the benchmark cannot disagree.

The simulation itself is seeded (SEED = 42 in qsafe_simulation.py), so
given the same two input times it reproduces Table 2 exactly, on any
machine, with or without liboqs installed.
"""
import os

from benchmark_pqc import load_results_from_csv
from pqc_config import (
    PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV, TABLE2_CSV, FIGURE_DIR,
    LEVEL3_KYBER, LEVEL3_FRODO,
)
from qsafe_simulation import extract_key_exchange_times, run_all_scenarios


def run_simulation(per_variant_csv: str = PER_VARIANT_CSV,
                   complete_csv: str = COMPLETE_EXCHANGE_CSV,
                   figure_dir: str = FIGURE_DIR,
                   table_csv_path: str = TABLE2_CSV,
                   show: bool = True):
    for path in (per_variant_csv, complete_csv):
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{path} not found -- run `python run_pqc_benchmark.py` first.")

    results = load_results_from_csv(per_variant_csv, complete_csv)

    kyber_time_s, frodo_time_s = extract_key_exchange_times(
        results["complete_key_exchange"], stat="median")

    print("Simulation inputs (medians, straight from "
          f"{complete_csv} -- not hand-entered):")
    print(f"  {LEVEL3_KYBER}: {kyber_time_s * 1000:.4f} ms per exchange")
    print(f"  {LEVEL3_FRODO}: {frodo_time_s * 1000:.4f} ms per exchange")
    print(f"  Ratio: {frodo_time_s / kyber_time_s:.1f}x\n")

    table2, sim_results = run_all_scenarios(
        kyber_time_s, frodo_time_s,
        save_dir=figure_dir, table_csv_path=table_csv_path, show=show)

    return table2, sim_results


if __name__ == "__main__":
    import matplotlib
    matplotlib.use("Agg")

    run_simulation(show=False)
