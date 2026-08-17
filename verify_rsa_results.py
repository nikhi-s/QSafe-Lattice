"""
verify_rsa_results.py
 
Pre-flight configuration validation and post-run data verification for the
RSA benchmark.
 
    python verify_rsa_results.py
 
preflight_check() is cheap and should be called BEFORE benchmarking, so a bad
configuration costs seconds instead of hours. verify_results() re-derives the
same expectation from run_config and asserts the CSV on disk matches it --
the expectation therefore cannot be tuned to fit the data.
"""
 
import pandas as pd
 
from rsa_implementation import max_oaep_plaintext_bytes
from run_config import KEY_SIZES, MESSAGE_SIZES, KEY_SIZE_SAMPLES
 
 
def preflight_check(verbose: bool = True) -> int:
    """Validate the run configuration and return the expected valid-row count."""
    assert sorted(KEY_SIZES) == KEY_SIZES, "KEY_SIZES should be ascending"
    assert set(KEY_SIZE_SAMPLES) == set(KEY_SIZES), \
        f"KEY_SIZE_SAMPLES keys {set(KEY_SIZE_SAMPLES)} != KEY_SIZES {set(KEY_SIZES)}"
    assert all(v > 0 for v in KEY_SIZE_SAMPLES.values()), "sample counts must be positive"
    assert all(m > 0 for m in MESSAGE_SIZES), "message sizes must be positive"
 
    ceilings = {k: max_oaep_plaintext_bytes(k) for k in KEY_SIZES}
    expected = 0
    if verbose:
        print("RSA-OAEP/SHA-256 plaintext limits and expected valid rows:")
        print(f"{'Key size':>9} {'Limit (B)':>10} {'Valid msg sizes':>34} {'Samples':>8} {'Rows':>6}")
    for k in KEY_SIZES:
        valid_sizes = [m for m in MESSAGE_SIZES if m <= ceilings[k]]
        assert valid_sizes, f"{k}-bit key: every message size exceeds its {ceilings[k]}B ceiling"
        rows = KEY_SIZE_SAMPLES[k] * len(valid_sizes)
        expected += rows
        if verbose:
            print(f"{k:>9} {ceilings[k]:>10} {str(valid_sizes):>34} {KEY_SIZE_SAMPLES[k]:>8} {rows:>6}")
    if verbose:
        print(f"{'':>9} {'':>10} {'':>34} {'TOTAL':>8} {expected:>6}")
        print("\nPre-flight config checks passed.")
    return expected
 
 
def verify_results(csv_path: str = "rsa_benchmark_results.csv"):
    """Assert the benchmark CSV on disk is complete, clean, and self-consistent."""
    # Re-derive the expectation from config. NOTE: this must be captured as a
    # local -- it is deliberately NOT a module-level constant, so that the
    # expected count can never drift from run_config.
    expected = preflight_check(verbose=False)
 
    df = pd.read_csv(csv_path)
    valid = df[df["skipped_reason"].isna()]
 
    # 1. Row count (catches incomplete, duplicated, or session-merged CSVs)
    assert len(valid) == expected, f"expected {expected} valid rows, got {len(valid)}"
 
    # 2. No missing timings hiding inside otherwise-valid rows
    nan_counts = valid[["encryption_time", "decryption_time", "key_gen_time"]].isna().sum()
    assert nan_counts.sum() == 0, f"valid rows contain missing timings:\n{nan_counts}"
 
    # 3. Ciphertext canary: mathematically fixed at key_size/8 bytes
    for k in KEY_SIZES:
        cts = set(df[df.key_size == k]["ciphertext_size"].dropna())
        assert cts == {k // 8}, f"ciphertext mismatch for {k}: {cts}"
 
    # 4. Key generation distribution (one value per sample, not per message-size row)
    print("Key generation time per key size (seconds):")
    kg = (df.drop_duplicates(subset=["key_size", "sample_idx"])
            .groupby("key_size")["key_gen_time"]
            .agg(["count", "median", "mean", "std", "min", "max"]).round(3))
    print(kg.to_string())
 
    print(f"\nAll post-run verification assertions passed ({len(valid)} valid rows).")
    return df
 
 
if __name__ == "__main__":
    preflight_check()
    verify_results()
