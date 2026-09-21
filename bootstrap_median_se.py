"""
bootstrap_median_se.py

Checks one specific claim made in the Discussion's limitations paragraph: that
pairing a MEDIAN (the reported centre) with a SEM (a standard error of the
MEAN) gives a conservative uncertainty bound on right-skewed timing data.

The two statistics describe different estimators, so the pairing needs
justification rather than assertion. This script supplies it.

METHOD. Bootstrap. Resample a configuration's trial times with replacement,
take the median of each resample, and the spread of those medians IS the
median's own standard error. Compare that against the SEM reported in Table 1
and in the figure error bars.

READ THE OUTPUT, DO NOT ASSUME THE ANSWER. The ratio is not uniform across
metrics. Decryption times are tightly clustered with occasional slow outliers,
so the median is pinned down well while those outliers inflate the standard
deviation and therefore the SEM -- there the SEM is much the larger of the two.
Key generation is different: prime search is intrinsically variable, so the
distribution is BROAD rather than merely tailed, and a median drawn from a
broad distribution is not especially well pinned either. Any claim in the
manuscript must match what this script actually prints.

Deliberately reads the algorithm and key-size lists out of the CSVs rather than
importing run_config / pqc_config, so the script is self-contained and runs
from either notebook without needing both pipelines present.

Seeded, and reads only the committed CSVs -- nothing is re-measured, and no
timing value in the manuscript can change by running this.

    python bootstrap_median_se.py
"""

import os

import numpy as np
import pandas as pd

N_RESAMPLES = 10000
SEED = 42

RSA_CSV = "rsa_benchmark_results.csv"
PQC_CSV = "pqc_benchmark_results.csv"


def bootstrap_se_median(samples, rng, n_resamples: int = N_RESAMPLES) -> float:
    """Standard error of the median, estimated by bootstrap resampling."""
    n = len(samples)
    medians = [np.median(rng.choice(samples, n, replace=True))
               for _ in range(n_resamples)]
    return float(np.std(medians, ddof=1))


def _row(label, metric, samples, rng):
    """One comparison line: median, SEM of the mean, bootstrap SE of the median."""
    sem = samples.std(ddof=1) / np.sqrt(len(samples))
    se_median = bootstrap_se_median(samples, rng)
    return {
        "config": label,
        "metric": metric,
        "n": len(samples),
        "median": float(np.median(samples)),
        "sem_of_mean": float(sem),
        "se_of_median": se_median,
        # >1 means the published error bar is WIDER than the median's real
        # uncertainty, i.e. conservative. <1 means it is too narrow.
        "ratio": float(sem / se_median) if se_median > 0 else float("nan"),
    }


def analyse_rsa(rng, csv_path: str = RSA_CSV, message_size: int = 16):
    """RSA: one row per key size per timed operation."""
    df = pd.read_csv(csv_path)
    df = df[(df.message_size == message_size) & (df.skipped_reason.isna())]

    rows = []
    for key_size in sorted(df.key_size.unique()):
        g = df[df.key_size == key_size]
        # Key generation happens once per key, not once per message, so the
        # rows must be de-duplicated or every value is counted seven times.
        rows.append(_row(f"RSA-{key_size}", "keygen (s)",
                         g.drop_duplicates(subset=["sample_idx"])["key_gen_time"].values, rng))
        rows.append(_row(f"RSA-{key_size}", "encrypt (ms)",
                         (g.encryption_time * 1000).values, rng))
        rows.append(_row(f"RSA-{key_size}", "decrypt (ms)",
                         (g.decryption_time * 1000).values, rng))
    return rows


def analyse_pqc(rng, csv_path: str = PQC_CSV):
    """Kyber and FrodoKEM: one row per variant per timed operation."""
    df = pd.read_csv(csv_path)
    rows = []
    for alg in sorted(df.algorithm.unique()):
        g = df[df.algorithm == alg]
        for col, label in [("keygen_time_s", "keygen (us)"),
                           ("encap_time_s", "encap (us)"),
                           ("decap_time_s", "decap (us)")]:
            rows.append(_row(alg, label, (g[col] * 1e6).values, rng))
    return rows


def report(rows, heading):
    print(f"\n{heading}")
    print(f"{'config':<20}{'metric':<14}{'n':>5}{'median':>12}"
          f"{'SEM(mean)':>12}{'SE(median)':>12}{'ratio':>8}")
    print("-" * 83)
    for r in rows:
        print(f"{r['config']:<20}{r['metric']:<14}{r['n']:>5}{r['median']:>12.5f}"
              f"{r['sem_of_mean']:>12.5f}{r['se_of_median']:>12.5f}{r['ratio']:>7.1f}x")


def main(rsa_csv: str = RSA_CSV, pqc_csv: str = PQC_CSV):
    rng = np.random.default_rng(SEED)
    print(f"Bootstrap standard error of the median "
          f"({N_RESAMPLES} resamples, seed {SEED})")
    print("ratio = SEM(mean) / SE(median).  >1 = published error bars are "
          "conservative;  <1 = too narrow.")

    all_rows = []

    if os.path.exists(rsa_csv):
        rows = analyse_rsa(rng, rsa_csv)
        report(rows, f"RSA  (from {rsa_csv}, 16-byte message)")
        all_rows += rows
    else:
        print(f"\n[skipped] {rsa_csv} not found.")

    if os.path.exists(pqc_csv):
        rows = analyse_pqc(rng, pqc_csv)
        report(rows, f"Kyber / FrodoKEM  (from {pqc_csv})")
        all_rows += rows
    else:
        print(f"\n[skipped] {pqc_csv} not found.")

    if not all_rows:
        raise SystemExit("No benchmark CSVs found -- run the benchmarks first.")

    conservative = [r for r in all_rows if r["ratio"] >= 1.0]
    too_narrow = [r for r in all_rows if r["ratio"] < 1.0]

    print(f"\n{'=' * 83}")
    print(f"{len(conservative)} of {len(all_rows)} measurements have "
          f"SEM >= SE(median)  (conservative).")
    if too_narrow:
        print(f"{len(too_narrow)} do NOT. The manuscript must not claim the bound "
              f"is conservative everywhere:")
        for r in too_narrow:
            print(f"    {r['config']:<20}{r['metric']:<14}ratio {r['ratio']:.1f}x")
    print("\nQuote in the Discussion only the range you can see above.")
    return all_rows


if __name__ == "__main__":
    main()
