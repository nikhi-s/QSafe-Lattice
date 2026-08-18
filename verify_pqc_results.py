"""
verify_pqc_results.py

Pre-flight configuration checks and post-run data assertions for the
Kyber / FrodoKEM benchmarks -- the KEM counterpart of
verify_rsa_results.py.

Two entry points, mirroring the RSA side:

    preflight_check()      run BEFORE the benchmark. Validates the config
                           and (if liboqs is installed) that every
                           mechanism named in pqc_config.py is actually
                           supported by this build. Catches a typo or a
                           liboqs built without FrodoKEM in two seconds
                           instead of an hour into the run.

    verify_pqc_results()   run AFTER the benchmark, on the two CSVs.
                           Trial counts, missing values, ciphertext
                           constants, FrodoKEM variant detection.

Standalone use:

    python verify_pqc_results.py          # pre-flight + verify the committed CSVs

All expected values come from pqc_config.py. Nothing in this file
restates a run parameter -- that duplication is exactly what caused the
drift this file now guards against.
"""
import os

import pandas as pd

from pqc_config import (
    KYBER_ALGS, FRODO_ALGS, LEVEL3_KYBER, LEVEL3_FRODO,
    KYBER_TRIALS, FRODO_TRIALS, NUM_WARMUP, MESSAGE_LENGTH_BYTES,
    PER_VARIANT_CSV, COMPLETE_EXCHANGE_CSV, expected_row_counts,
)

# Ciphertext sizes are protocol constants -- the canary for column drift
# and for a silently changed algorithm variant. They are verification
# constants, not run parameters, which is why they live here and not in
# pqc_config.py. Kyber's are stable across liboqs versions; FrodoKEM's
# depend on which variant liboqs ships: pre-ISO (unsalted) vs.
# ISO-standardized (salted, +32/+48/+64 bytes).
KYBER_CT = {"Kyber512": 768, "Kyber768": 1088, "Kyber1024": 1568}
FRODO_CT_PRE_ISO = {"FrodoKEM-640-AES": 9720, "FrodoKEM-976-AES": 15744,
                    "FrodoKEM-1344-AES": 21632}
FRODO_CT_ISO = {"FrodoKEM-640-AES": 9752, "FrodoKEM-976-AES": 15792,
                "FrodoKEM-1344-AES": 21696}


def preflight_check(verbose: bool = True) -> dict:
    """
    Validate the run configuration BEFORE spending an hour measuring.
    Returns the expected row counts so the caller does not have to
    recompute them.

    Checks, in order of how much time each one saves:

      1. liboqs actually supports every mechanism named in the config.
         A liboqs built without FrodoKEM enabled, or a mechanism name
         that changed between versions, fails here in seconds rather
         than after the Kyber half has already run.
      2. Trial counts are positive integers.
      3. The level-3 pair named for the complete-key-exchange comparison
         is present in the per-variant algorithm lists -- otherwise the
         two CSVs describe different algorithm sets.
      4. Warm-up count is non-negative and smaller than the trial count.

    Skips check 1 when liboqs is not installed, so this function still
    runs in a --reuse-csv workflow on a machine that never built liboqs.
    """
    counts = expected_row_counts()

    assert isinstance(KYBER_TRIALS, int) and KYBER_TRIALS > 0, \
        f"KYBER_TRIALS must be a positive int, got {KYBER_TRIALS!r}"
    assert isinstance(FRODO_TRIALS, int) and FRODO_TRIALS > 0, \
        f"FRODO_TRIALS must be a positive int, got {FRODO_TRIALS!r}"
    assert 0 <= NUM_WARMUP < min(KYBER_TRIALS, FRODO_TRIALS), \
        f"NUM_WARMUP ({NUM_WARMUP}) must be >= 0 and smaller than the trial counts"
    assert MESSAGE_LENGTH_BYTES > 0, "MESSAGE_LENGTH_BYTES must be positive"

    assert LEVEL3_KYBER in KYBER_ALGS, \
        f"LEVEL3_KYBER ({LEVEL3_KYBER}) is not in KYBER_ALGS -- the two CSVs " \
        f"would cover different algorithm sets"
    assert LEVEL3_FRODO in FRODO_ALGS, \
        f"LEVEL3_FRODO ({LEVEL3_FRODO}) is not in FRODO_ALGS -- the two CSVs " \
        f"would cover different algorithm sets"

    # Mechanism-support check. Import is local and guarded so this module
    # stays usable without liboqs.
    try:
        import oqs
    except ImportError:
        oqs = None

    if oqs is None:
        if verbose:
            print("liboqs not installed -- skipping the mechanism-support check.")
            print("(Fine for --reuse-csv; a live benchmark run needs liboqs.)")
    else:
        supported = set(oqs.get_supported_kem_mechanisms())
        missing = [a for a in KYBER_ALGS + FRODO_ALGS if a not in supported]
        assert not missing, (
            f"liboqs does not support: {missing}. Either the mechanism names in "
            f"pqc_config.py are wrong for this liboqs version, or this build was "
            f"compiled without them. Check oqs.get_supported_kem_mechanisms()."
        )
        if verbose:
            print(f"liboqs {oqs.oqs_version()} supports all "
                  f"{len(KYBER_ALGS) + len(FRODO_ALGS)} required mechanisms.")

    if verbose:
        total_pv = sum(counts["per_variant"].values())
        total_cx = sum(counts["complete_key_exchange"].values())
        print(f"\nPre-flight configuration check")
        print(f"  Kyber variants:   {', '.join(KYBER_ALGS)} @ {KYBER_TRIALS} trials")
        print(f"  FrodoKEM variants: {', '.join(FRODO_ALGS)} @ {FRODO_TRIALS} trials")
        print(f"  Level-3 pair:      {LEVEL3_KYBER} vs {LEVEL3_FRODO}")
        print(f"  Warm-ups discarded: {NUM_WARMUP} per algorithm")
        print(f"  Expected rows: {total_pv} in {PER_VARIANT_CSV}, "
              f"{total_cx} in {COMPLETE_EXCHANGE_CSV}")
        print("  Pre-flight checks passed.\n")

    return counts


def verify_pqc_results(per_variant_csv: str = PER_VARIANT_CSV,
                       complete_csv: str = COMPLETE_EXCHANGE_CSV):
    """Post-run assertions on the two CSVs. Raises on any inconsistency."""
    for path in (per_variant_csv, complete_csv):
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{path} not found. Run the benchmark first "
                f"(python run_pqc_benchmark.py), or point this function at the "
                f"committed CSV."
            )

    expected = expected_row_counts()
    pv = pd.read_csv(per_variant_csv)

    # 1. Trial counts per variant -- expectations come from pqc_config.py,
    #    so they cannot disagree with what the benchmark was told to do.
    counts = pv.groupby("algorithm").size()
    for alg, n_expected in expected["per_variant"].items():
        assert counts.get(alg, 0) == n_expected, \
            f"{alg}: {counts.get(alg, 0)} trials in CSV, expected {n_expected}"

    # 2. No missing timings
    assert pv[["keygen_time_s", "encap_time_s", "decap_time_s"]].isna().sum().sum() == 0, \
        "NaN timings present -- a trial failed silently"

    # 3. Ciphertext constants, and detect which FrodoKEM variant liboqs shipped
    ct = pv.groupby("algorithm")["ciphertext_size_bytes"].agg(lambda s: set(s))
    for alg, expected_ct in KYBER_CT.items():
        assert ct[alg] == {expected_ct}, \
            f"{alg} ciphertext {ct[alg]}, expected {{{expected_ct}}}"

    frodo_measured = {alg: ct[alg] for alg in FRODO_ALGS}
    if all(frodo_measured[a] == {FRODO_CT_ISO[a]} for a in FRODO_ALGS):
        variant = "ISO-standardized FrodoKEM (salted ciphertexts)"
    elif all(frodo_measured[a] == {FRODO_CT_PRE_ISO[a]} for a in FRODO_ALGS):
        variant = "pre-ISO FrodoKEM (unsalted ciphertexts)"
    else:
        raise AssertionError(
            f"FrodoKEM ciphertexts match neither known variant: {frodo_measured}")
    print(f"FrodoKEM variant detected: {variant}")
    print("STATE THIS IN METHODS along with the liboqs version -- the ciphertext sizes")
    print("in the manuscript must match this variant, not the other one.")

    # 4. Complete-key-exchange medians -- the Q-Safe inputs and Table 2 basis
    cx = pd.read_csv(complete_csv)
    cx_counts = cx.groupby("algorithm").size()
    for alg, n_expected in expected["complete_key_exchange"].items():
        assert cx_counts.get(alg, 0) == n_expected, \
            f"{alg} (complete exchange): {cx_counts.get(alg, 0)} trials, expected {n_expected}"

    med = cx.groupby("algorithm")["total_time_s"].median()
    k, f = med[LEVEL3_KYBER] * 1000, med[LEVEL3_FRODO] * 1000
    print(f"\nComplete key exchange (median): {LEVEL3_KYBER} {k:.4f} ms | "
          f"{LEVEL3_FRODO} {f:.4f} ms | ratio {f / k:.1f}x")
    print("These are the ONLY authoritative per-exchange values -- Table 2, the Q-Safe")
    print("figures, and every text claim must use these, not docstring examples.")
    print("\nAll PQC verification assertions passed.")

    return pv, cx


if __name__ == "__main__":
    preflight_check()
    verify_pqc_results()
