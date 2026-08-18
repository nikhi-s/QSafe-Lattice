"""
generate_pqc_figure3.py

Figure 3 -- Kyber vs. FrodoKEM at matched NIST security levels (2x2
panels: key generation, encapsulation, decapsulation, ciphertext size).
The KEM counterpart of generate_rsa_table_and_figure.py.

Reads the committed CSVs rather than taking a live benchmark result, so
the figure can be regenerated on any machine, with or without liboqs,
without re-measuring anything.

    python generate_pqc_figure3.py

Also prints the headline numbers the Results text quotes, so the figure
and the sentence next to it cannot drift apart.
"""
import os

from benchmark_pqc import load_results_from_csv
from plot_pqc_comparison import plot_figure4
from pqc_config import (
    PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV, FIGURE_DIR,
    LEVEL3_KYBER, LEVEL3_FRODO, KYBER_ALGS, FRODO_ALGS,
)

FIGURE3_PATH = os.path.join(FIGURE_DIR, "Figure 3 - Kyber vs FrodoKEM Performance.png")


def generate_figure3(per_variant_csv: str = PER_VARIANT_CSV,
                     complete_csv: str = COMPLETE_EXCHANGE_CSV,
                     figure_path: str = FIGURE3_PATH,
                     show: bool = True):
    for path in (per_variant_csv, complete_csv):
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{path} not found -- run `python run_pqc_benchmark.py` first.")

    results = load_results_from_csv(per_variant_csv, complete_csv)

    plot_figure4(results["per_variant"], stat="median", error_bar_type="sem",
                 color_style="gradient", save_path=figure_path, show=show)

    # The numbers the Results paragraph quotes, printed from the same data
    # the figure was drawn from. Quoting anything else is how a caption and
    # a sentence end up disagreeing.
    cx = results["complete_key_exchange"]
    k_ms = cx[LEVEL3_KYBER]["median_time_s"] * 1000
    f_ms = cx[LEVEL3_FRODO]["median_time_s"] * 1000

    print("\nNumbers for the Results text (medians, from the same CSVs):")
    print(f"  Complete key exchange: {LEVEL3_KYBER} {k_ms:.4f} ms | "
          f"{LEVEL3_FRODO} {f_ms:.4f} ms")
    print(f"  Speed ratio: {f_ms / k_ms:.1f}x")

    pv = results["per_variant"]
    print("\n  Ciphertext sizes (bytes) -- protocol constants, so one value each:")
    for alg in KYBER_ALGS + FRODO_ALGS:
        print(f"    {alg:22} {int(pv[alg]['ciphertext_size_bytes'])}")

    # The size ratio the Results text quotes, level for level.
    print("\n  FrodoKEM / Kyber ciphertext size ratio, by security level:")
    for k_alg, f_alg in zip(KYBER_ALGS, FRODO_ALGS):
        ratio = pv[f_alg]["ciphertext_size_bytes"] / pv[k_alg]["ciphertext_size_bytes"]
        print(f"    {k_alg} vs {f_alg}: {ratio:.1f}x")

    return results


if __name__ == "__main__":
    import matplotlib
    matplotlib.use("Agg")

    generate_figure3(show=False)
