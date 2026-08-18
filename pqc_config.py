"""
pqc_config.py

Single source of truth for the Kyber / FrodoKEM benchmark run parameters --
the KEM counterpart of run_config.py on the RSA side.

WHY THIS FILE EXISTS
--------------------
Before it, the trial counts lived in two unconnected places:

  * the notebook called run_full_benchmark_suite(num_trials=100,
    kyber_num_trials=500), and
  * verify_pqc_results.py separately hardcoded KYBER_TRIALS = 500 and
    FRODO_TRIALS = 100.

Nothing tied those together. Change one and forget the other and the
verification either fails on data that was actually fine, or -- worse --
passes while checking the wrong thing. The benchmark, the pre-flight
check and the post-run assertions now all read the constants below, so
the numbers being asserted can never drift from the numbers that ran.

This is exactly the role run_config.py plays for RSA. Same reason, same
shape.

CHANGING THESE VALUES INVALIDATES THE PUBLISHED DATA. The manuscript's
Table 2, Figures 3-5 and every quoted per-exchange time come from one
frozen run at the values below. Edit them only if you intend to re-run
the whole KEM pipeline and re-derive every downstream number.
"""

# --- Algorithm sets -----------------------------------------------------
# liboqs mechanism names, exactly as oqs.get_supported_kem_mechanisms()
# reports them. A typo here surfaces in the pre-flight check rather than
# an hour into the run.
KYBER_ALGS = ["Kyber512", "Kyber768", "Kyber1024"]
FRODO_ALGS = ["FrodoKEM-640-AES", "FrodoKEM-976-AES", "FrodoKEM-1344-AES"]

# The matched-security-level pair used for the complete-key-exchange
# comparison and as the Q-Safe simulation's timing inputs. Both are NIST
# security level 3 -- that matching is the entire basis for the "54.6x"
# claim, so it is named here rather than buried in a function body.
LEVEL3_KYBER = "Kyber768"
LEVEL3_FRODO = "FrodoKEM-976-AES"

# --- Trial counts -------------------------------------------------------
# Kyber operations run in the tens of microseconds, where OS scheduling
# jitter is a large fraction of the signal; FrodoKEM's are milliseconds,
# where it is not. More Kyber trials tighten its interval at almost no
# wall-clock cost, so the two families are sampled differently on purpose.
# (Same reasoning as RSA-1024's 500 samples in run_config.py.)
KYBER_TRIALS = 500
FRODO_TRIALS = 100

# Untimed calls discarded before measurement begins. The first operation
# against a fresh key costs noticeably more than a steady-state one; left
# in, that artifact attaches itself to whichever measurement happened to
# run first.
NUM_WARMUP = 5

# Plaintext length handed to the KEM harness, in bytes. KEM ciphertext
# sizes do not depend on it -- it is fixed only so the runs are identical.
MESSAGE_LENGTH_BYTES = 64

# --- Output paths -------------------------------------------------------
# CSVs stay at the repository root (matching rsa_benchmark_results.csv);
# every generated image goes to FIGURE_DIR, which the scripts create.
PER_VARIANT_CSV = "pqc_benchmark_results.csv"
COMPLETE_EXCHANGE_CSV = "pqc_complete_key_exchange_results.csv"
TABLE2_CSV = "Table 2 - Q-Safe Simulation Results.csv"
FIGURE_DIR = "figures"


def expected_row_counts() -> dict:
    """
    Row counts each CSV must contain if the run completed correctly.
    Returned as data rather than printed, so the pre-flight check, the
    post-run assertions and any ad-hoc inspection all quote the same
    numbers.
    """
    per_variant = {alg: KYBER_TRIALS for alg in KYBER_ALGS}
    per_variant.update({alg: FRODO_TRIALS for alg in FRODO_ALGS})
    complete = {LEVEL3_KYBER: KYBER_TRIALS, LEVEL3_FRODO: FRODO_TRIALS}
    return {"per_variant": per_variant, "complete_key_exchange": complete}
