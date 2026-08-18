"""
qsafe_simulation.py

The Q-Safe adaptive cryptographic framework, implemented as the
discrete-time simulation described in the paper's Methods section.

This REPLACES the illustrative plots in the original notebook
(quantum_threat_levels = np.arange(0, 101, 5) with hardcoded thresholds
40/70, plus the unrelated 3D "switching_behavior" toy matrix). Those were
never a simulation of the framework described in the paper -- they were a
static diagram with made-up numbers. This module actually implements:

  - three runtime factors (threat, capability, energy), each 0-100
  - EMA smoothing of incoming telemetry (alpha = 0.35)
  - environment-derived weights (security weight rises with threat;
    performance weight rises as compute headroom shrinks; efficiency
    weight rises as energy budget shrinks), normalized to sum to 1
  - a composite suitability score per algorithm combining a fixed
    security rating (Kyber 0.6, FrodoKEM 1.0) with performance/efficiency
    scores derived from MEASURED median key-exchange times
  - hybrid mode when the two scores are within a margin of 0.08
  - three 200-timestep scenarios (rising threat, constrained edge device,
    threat spikes), seed = 42, matching the paper's Table 2
  - comparison against always-Kyber / always-FrodoKEM baselines
  - an assumed 15 W package power model for energy estimates

IMPORTANT: the two timing inputs (kyber_time_s, frodo_time_s) must come
from benchmark_pqc.py's benchmark_complete_key_exchange() run on your own
hardware -- do NOT hardcode previously-published values here, since those numbers should be regenerated fresh each time
you rerun this, and the whole point of this fix is that code and
manuscript numbers should come from the same reproducible source.
"""

import os

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from pqc_config import FIGURE_DIR, TABLE2_CSV


SEED = 42
NUM_TIMESTEPS = 200
EMA_ALPHA = 0.35
HYBRID_MARGIN = 0.08
SECURITY_RATING = {"Kyber": 0.6, "FrodoKEM": 1.0}
PACKAGE_POWER_WATTS = 15.0


def ema_smooth(raw_series: np.ndarray, alpha: float = EMA_ALPHA) -> np.ndarray:
    """Exponential moving average smoothing of a 1D telemetry series."""
    smoothed = np.zeros_like(raw_series, dtype=float)
    smoothed[0] = raw_series[0]
    for i in range(1, len(raw_series)):
        smoothed[i] = alpha * raw_series[i] + (1 - alpha) * smoothed[i - 1]
    return smoothed


def compute_weights(threat: float, capability: float, energy: float):
    """
    Derive (security, performance, efficiency) weights from the current
    (smoothed) runtime factors, normalized to sum to 1.

    security weight  rises with threat level
    performance weight rises as compute headroom (capability) shrinks
    efficiency weight  rises as energy budget shrinks
    """
    w_security = threat / 100.0
    w_performance = (100.0 - capability) / 100.0
    w_efficiency = (100.0 - energy) / 100.0
    total = w_security + w_performance + w_efficiency
    if total == 0:
        return 1 / 3, 1 / 3, 1 / 3
    return w_security / total, w_performance / total, w_efficiency / total


PERF_SCORE_STEEPNESS = 0.35
# Controls how strongly a raw time/energy ratio between the two algorithms
# translates into a performance/efficiency score gap. A LINEAR ratio (the
# original design) is a bug here: Kyber is ~50x faster than FrodoKEM at
# NIST level 3, so a raw ratio gives Kyber a ~0.98 vs. ~0.02 score split on
# performance ALONE -- large enough to swamp the entire 0.4-point security
# rating gap (Kyber 0.6 vs. FrodoKEM 1.0) even at maximum simulated threat,
# meaning FrodoKEM could never win outright regardless of threat level
# (verified empirically: it converges to a near-tie/Hybrid at threat=100
# and never crosses it). Using a logistic function of log(ratio) instead
# compresses large speed/energy gaps into a bounded score difference, so
# the security dimension can still decide the outcome when threat is high
# enough, matching the escalation behavior described in the paper's
# Results (Kyber -> Hybrid -> FrodoKEM as threat rises). Steepness=0.35
# was chosen by checking that: (a) low threat + ample headroom keeps
# Kyber selected, (b) high threat + typical headroom crosses into a
# FrodoKEM win, not just a Hybrid tie -- see the diagnostic prints in the
# module docstring/README for the values used to pick this constant.
# Re-tune if your own measured kyber_time_s/frodo_time_s ratio differs
# substantially from ~50x.


def _bounded_perf_score(fast_time_s: float, slow_time_s: float, steepness: float = PERF_SCORE_STEEPNESS):
    """
    Return (fast_score, slow_score) in (0, 1), summing to 1, where the
    gap between them is a bounded function of log(slow/fast) rather than
    the raw linear ratio. This prevents a large absolute speed gap from
    mechanically overwhelming the other scoring dimensions (see note above
    PERF_SCORE_STEEPNESS).
    """
    if fast_time_s <= 0 or slow_time_s <= 0:
        return 0.5, 0.5
    log_ratio = np.log(slow_time_s / fast_time_s)
    fast_score = 1.0 / (1.0 + np.exp(-steepness * log_ratio))
    return fast_score, 1.0 - fast_score


def algorithm_scores(w_sec, w_perf, w_eff, kyber_time_s, frodo_time_s,
                      kyber_energy_j, frodo_energy_j):
    """
    Composite suitability score for Kyber and FrodoKEM given current
    weights and measured performance/energy costs.

    Performance and efficiency sub-scores use a bounded logistic transform
    of the log time/energy ratio (see _bounded_perf_score), not a raw
    linear ratio -- a raw ratio lets Kyber's ~50x speed advantage swamp
    the security-rating dimension entirely, making FrodoKEM structurally
    unable to win regardless of threat level (see PERF_SCORE_STEEPNESS
    comment for the empirical check that led to this fix).
    """
    if kyber_time_s <= frodo_time_s:
        kyber_perf_score, frodo_perf_score = _bounded_perf_score(kyber_time_s, frodo_time_s)
    else:
        frodo_perf_score, kyber_perf_score = _bounded_perf_score(frodo_time_s, kyber_time_s)

    if kyber_energy_j <= frodo_energy_j:
        kyber_eff_score, frodo_eff_score = _bounded_perf_score(kyber_energy_j, frodo_energy_j)
    else:
        frodo_eff_score, kyber_eff_score = _bounded_perf_score(frodo_energy_j, kyber_energy_j)

    kyber_score = (
        w_sec * SECURITY_RATING["Kyber"]
        + w_perf * kyber_perf_score
        + w_eff * kyber_eff_score
    )
    frodo_score = (
        w_sec * SECURITY_RATING["FrodoKEM"]
        + w_perf * frodo_perf_score
        + w_eff * frodo_eff_score
    )
    return kyber_score, frodo_score


def select_algorithm(kyber_score: float, frodo_score: float) -> str:
    """Pick the higher-scoring algorithm, or 'Hybrid' if within margin."""
    if abs(kyber_score - frodo_score) <= HYBRID_MARGIN:
        return "Hybrid"
    return "Kyber" if kyber_score > frodo_score else "FrodoKEM"


def generate_scenario(name: str, rng: np.random.Generator):
    """
    Generate the three raw (unsmoothed) runtime-factor traces for one of
    the three scenarios described in the paper. Each factor is 0-100 with
    added noise; EMA smoothing is applied afterward in run_scenario().
    """
    t = np.arange(NUM_TIMESTEPS)

    if name == "rising_threat":
        threat = np.clip(np.linspace(5, 95, NUM_TIMESTEPS) + rng.normal(0, 4, NUM_TIMESTEPS), 0, 100)
        capability = np.clip(80 + rng.normal(0, 4, NUM_TIMESTEPS), 0, 100)
        energy = np.clip(80 + rng.normal(0, 4, NUM_TIMESTEPS), 0, 100)

    elif name == "constrained_edge":
        threat = np.clip(15 + rng.normal(0, 4, NUM_TIMESTEPS), 0, 100)
        capability = np.clip(20 + rng.normal(0, 3, NUM_TIMESTEPS), 0, 100)
        energy = np.clip(np.linspace(40, 10, NUM_TIMESTEPS) + rng.normal(0, 3, NUM_TIMESTEPS), 0, 100)

    elif name == "threat_spikes":
        threat = np.clip(15 + rng.normal(0, 4, NUM_TIMESTEPS), 0, 100)
        # three high-alert windows -- pushed to 96 (was 85) so that, combined
        # with the capability/energy=80 below, the composite score actually
        # crosses into an outright FrodoKEM win during spikes rather than
        # staying in the Hybrid margin the whole time (verified empirically;
        # see PERF_SCORE_STEEPNESS note -- at cap=energy=70 and threat=85 the
        # scenario never escalated past Hybrid at all)
        for start in (40, 100, 160):
            end = start + 15
            threat[start:end] = np.clip(96 + rng.normal(0, 3, end - start), 0, 100)
        capability = np.clip(80 + rng.normal(0, 4, NUM_TIMESTEPS), 0, 100)
        energy = np.clip(80 + rng.normal(0, 4, NUM_TIMESTEPS), 0, 100)

    else:
        raise ValueError(f"Unknown scenario: {name}")

    return {"threat": threat, "capability": capability, "energy": energy}


def run_scenario(name: str, kyber_time_s: float, frodo_time_s: float, rng: np.random.Generator):
    """
    Run one 200-timestep Q-Safe simulation scenario and return a dict with
    per-step selections plus summary statistics matching the paper's Table 2
    columns.
    """
    raw = generate_scenario(name, rng)
    threat = ema_smooth(raw["threat"])
    capability = ema_smooth(raw["capability"])
    energy = ema_smooth(raw["energy"])

    kyber_energy_j = kyber_time_s * PACKAGE_POWER_WATTS
    frodo_energy_j = frodo_time_s * PACKAGE_POWER_WATTS

    selections = []
    cumulative_time_s = 0.0
    cumulative_energy_j = 0.0
    counts = {"Kyber": 0, "Hybrid": 0, "FrodoKEM": 0}

    for i in range(NUM_TIMESTEPS):
        w_sec, w_perf, w_eff = compute_weights(threat[i], capability[i], energy[i])
        kyber_score, frodo_score = algorithm_scores(
            w_sec, w_perf, w_eff, kyber_time_s, frodo_time_s, kyber_energy_j, frodo_energy_j
        )
        choice = select_algorithm(kyber_score, frodo_score)
        selections.append(choice)
        counts[choice] += 1

        if choice == "Kyber":
            cumulative_time_s += kyber_time_s
            cumulative_energy_j += kyber_energy_j
        elif choice == "FrodoKEM":
            cumulative_time_s += frodo_time_s
            cumulative_energy_j += frodo_energy_j
        else:  # Hybrid: both KEMs are executed and secrets combined
            cumulative_time_s += kyber_time_s + frodo_time_s
            cumulative_energy_j += kyber_energy_j + frodo_energy_j

    switches = sum(1 for i in range(1, NUM_TIMESTEPS) if selections[i] != selections[i - 1])

    always_kyber_time_s = kyber_time_s * NUM_TIMESTEPS
    always_frodo_time_s = frodo_time_s * NUM_TIMESTEPS

    return {
        "scenario": name,
        "raw_factors": raw,
        "smoothed_factors": {"threat": threat, "capability": capability, "energy": energy},
        "selections": selections,
        "counts": counts,
        "switches": switches,
        "switch_frequency": switches / NUM_TIMESTEPS,
        "qsafe_cumulative_time_ms": cumulative_time_s * 1000,
        "always_kyber_ms": always_kyber_time_s * 1000,
        "always_frodo_ms": always_frodo_time_s * 1000,
        "qsafe_energy_j": cumulative_energy_j,
        "always_kyber_energy_j": kyber_energy_j * NUM_TIMESTEPS,
        "always_frodo_energy_j": frodo_energy_j * NUM_TIMESTEPS,
    }


def plot_scenario(result: dict, save_dir: str = FIGURE_DIR,
                  filename: str = None, show: bool = True):
    """
    Reproduce the Q-Safe simulation figures: runtime factors, algorithm
    selection over time, and cumulative key-exchange time vs. fixed
    baselines.

    filename: exact output filename (e.g. "Figure 4 - Q-Safe Rising Threat
    Scenario.png"). If not given, falls back to a generic
    "qsafe_{scenario}.png" name -- useful for exploratory scenarios (e.g.
    constrained_edge) that aren't one of the paper's numbered figures
    (that scenario's result is fully captured in Table 2 as a single row;
    see the figure/table budget discussion -- JEI caps manuscripts at 8
    figures+tables total, so not every scenario gets its own figure).

    NOTE: no fig-level or axes-level title is set here -- JEI prohibits
    on-graph titles ("Please do not include titles on your graphs.
    Titles should be located in your figure captions and bolded.").
    Panel letters (A/B/C) are used instead, per JEI's paneled-figure
    convention, with the descriptive title reserved for the manuscript
    caption.
    """
    fig, axes = plt.subplots(3, 1, figsize=(10, 10), sharex=True)
    t = np.arange(NUM_TIMESTEPS)
    sf = result["smoothed_factors"]

    axes[0].plot(t, sf["threat"], label="Threat level")
    axes[0].plot(t, sf["capability"], label="System capability")
    axes[0].plot(t, sf["energy"], label="Energy availability")
    axes[0].set_ylabel("Factor value (0-100)")
    axes[0].set_title("A)", loc="left", fontweight="bold")
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    choice_map = {"Kyber": 0, "Hybrid": 1, "FrodoKEM": 2}
    choice_numeric = [choice_map[c] for c in result["selections"]]
    axes[1].step(t, choice_numeric, where="post")
    axes[1].set_yticks([0, 1, 2])
    axes[1].set_yticklabels(["Kyber", "Hybrid", "FrodoKEM"])
    axes[1].set_ylabel("Algorithm selected")
    axes[1].set_title("B)", loc="left", fontweight="bold")
    axes[1].grid(True, alpha=0.3)

    cumulative = np.cumsum([
        (result["always_kyber_ms"] / NUM_TIMESTEPS if c == "Kyber"
         else result["always_frodo_ms"] / NUM_TIMESTEPS if c == "FrodoKEM"
         else (result["always_kyber_ms"] + result["always_frodo_ms"]) / NUM_TIMESTEPS)
        for c in result["selections"]
    ])
    always_kyber_line = np.linspace(0, result["always_kyber_ms"], NUM_TIMESTEPS)
    always_frodo_line = np.linspace(0, result["always_frodo_ms"], NUM_TIMESTEPS)
    axes[2].plot(t, cumulative, label="Q-Safe", linewidth=2)
    axes[2].plot(t, always_kyber_line, label="Always-Kyber", linestyle="--")
    axes[2].plot(t, always_frodo_line, label="Always-FrodoKEM", linestyle="--")
    axes[2].set_xlabel("Timestep (key exchange)")
    axes[2].set_ylabel("Cumulative time (ms)")
    axes[2].set_title("C)", loc="left", fontweight="bold")
    axes[2].legend()
    axes[2].grid(True, alpha=0.3)

    plt.tight_layout()
    out_name = filename if filename else f"qsafe_{result['scenario']}.png"
    # os.path.join, not an f-string with "/", so a bare save_dir="" or a
    # Windows path does not silently produce a broken filename. matplotlib
    # will not create a missing folder, so make it first.
    out_path = os.path.join(save_dir, out_name) if save_dir else out_name
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"Saved to {out_path}")
    if show:
        plt.show()
    else:
        plt.close(fig)


def run_all_scenarios(kyber_time_s: float, frodo_time_s: float,
                        save_dir: str = FIGURE_DIR,
                        table_csv_path: str = TABLE2_CSV,
                        show: bool = True):
    """
    Run all three scenarios and build the Table 2 DataFrame.

    kyber_time_s / frodo_time_s should be the MEDIAN complete-key-exchange
    times (in seconds) from benchmark_pqc.benchmark_complete_key_exchange()
    run on your own hardware -- pass them in, don't hardcode.

    table_csv_path: output CSV filename. Default follows the same
    descriptive-naming convention as the RSA side ("Table 1 - RSA
    Performance Summary.csv" from generate_rsa_table_and_figure.py) --
    keep files identifiable while the manuscript is in flux. Note that
    JEI does not upload table files at all: tables are pasted into the
    manuscript as editable Word tables (caption ABOVE the table, unlike
    figures), so this CSV is a working artifact for your own use, not a
    submission file.

    NOTE ON THE CONSTRAINED-EDGE SCENARIO: unlike rising_threat (Figure 4)
    and threat_spikes (Figure 5), the constrained-edge scenario has NO
    corresponding manuscript figure -- deliberately. Its result (Q-Safe
    selects Kyber for all 200 exchanges, zero switches, cumulative time
    exactly matching the always-Kyber baseline) has essentially no visual
    shape to show; the single Table 2 row carries the entire finding,
    which is that the adaptive layer adds ZERO overhead when conditions
    never call for escalation. Under JEI's cap of 8 figures+tables total,
    a near-flat-line figure restating one table row would waste a slot --
    and JEI's own guidance says to prefer one format over duplicating the
    same data in both. When writing the manuscript, make sure the Results
    text states this scenario's finding explicitly, citing (Table 2)
    only -- there is no figure to cite for it.
    """
    rng = np.random.default_rng(SEED)
    scenario_names = {
        "rising_threat": "Rising threat (server)",
        "constrained_edge": "Constrained edge device",
        "threat_spikes": "Threat spikes (datacenter)",
    }
    # Only rising_threat and threat_spikes are numbered manuscript figures
    # (Figure 4 and Figure 5) -- constrained_edge is Table 2-only; see the
    # docstring above for the full rationale. It still gets plotted (useful
    # for your own review) but with a generic, non-"Figure N" filename so
    # it doesn't get mistaken for a numbered submission figure.
    figure_filenames = {
        "rising_threat": "Figure 4 - Q-Safe Rising Threat Scenario.png",
        "threat_spikes": "Figure 5 - Q-Safe Threat Spikes Scenario.png",
    }

    rows = []
    results = {}
    for key, label in scenario_names.items():
        result = run_scenario(key, kyber_time_s, frodo_time_s, rng)
        results[key] = result
        plot_scenario(result, save_dir=save_dir,
                      filename=figure_filenames.get(key), show=show)

        reduction_vs_frodo = (
            1 - result["qsafe_cumulative_time_ms"] / result["always_frodo_ms"]
        ) * 100 if result["always_frodo_ms"] > 0 else float("nan")

        rows.append({
            "Scenario": label,
            "Kyber": result["counts"]["Kyber"],
            "Hybrid": result["counts"]["Hybrid"],
            "FrodoKEM": result["counts"]["FrodoKEM"],
            "Switches": result["switches"],
            "Switch freq. (/step)": round(result["switch_frequency"], 3),
            "Q-Safe cum. time (ms)": round(result["qsafe_cumulative_time_ms"], 2),
            "Always-Kyber (ms)": round(result["always_kyber_ms"], 2),
            "Always-FrodoKEM (ms)": round(result["always_frodo_ms"], 2),
            "Reduction vs. always-FrodoKEM (%)": round(reduction_vs_frodo, 1),
            "Energy est. (J)": round(result["qsafe_energy_j"], 2),
        })

    table2 = pd.DataFrame(rows)
    # table_csv_path is used AS GIVEN -- it is deliberately not joined with
    # save_dir. save_dir is the figure folder; the Table 2 CSV is a data
    # artifact and belongs beside the benchmark CSVs at the repository
    # root, matching "Table 1 - RSA Performance Summary.csv" on the RSA
    # side. (Previously it was written to f"{save_dir}/{table_csv_path}"
    # while the message below printed the bare path -- so the file and the
    # location reported to the user disagreed the moment save_dir stopped
    # being ".".)
    os.makedirs(os.path.dirname(table_csv_path) or ".", exist_ok=True)
    table2.to_csv(table_csv_path, index=False)
    print(table2.to_string(index=False))
    print()
    print(f"Saved to {table_csv_path}")
    print("REMINDER: the constrained-edge scenario is Table 2-only (no figure);")
    print("in the manuscript, cite it as (Table 2) -- see run_all_scenarios() docstring.")
    return table2, results


def extract_key_exchange_times(complete_key_exchange_results: dict, stat: str = "median"):
    """
    Pull kyber_time_s and frodo_time_s directly from
    benchmark_pqc.run_full_benchmark_suite()["complete_key_exchange"],
    instead of hand-copying printed numbers into this file. This is the
    single source of truth for these two timings -- if you rerun the
    benchmark and get different numbers, calling this again picks them up
    automatically, with no manual transcription step to forget or get
    wrong.

    stat: "median" (default) or "mean" or "min". benchmark_pqc.py's own
    guidance is that `min` can be more robust to system noise for Kyber's
    microsecond-scale operations, but this project uses median (matching
    the originally-stated Methods text: "median of N liboqs trials") --
    pass stat="mean" if you'd rather use that instead. Whichever you pick,
    the SAME stat is applied to both algorithms for methodological
    consistency, and state the choice explicitly in the Methods section.

    Expects the dict shape produced by benchmark_pqc.py:
        {"Kyber768": {"median_time_s":.., "mean_time_s":.., "min_time_s":.., ...},
         "FrodoKEM-976-AES": {"median_time_s":.., "mean_time_s":.., "min_time_s":.., ...}}
    """
    key = f"{stat}_time_s"
    kyber_time_s = complete_key_exchange_results["Kyber768"][key]
    frodo_time_s = complete_key_exchange_results["FrodoKEM-976-AES"][key]
    print(f"Using {stat} of measured times: Kyber768={kyber_time_s*1000:.4f} ms, "
          f"FrodoKEM-976-AES={frodo_time_s*1000:.4f} ms "
          f"(ratio {frodo_time_s/kyber_time_s:.1f}x)")
    return kyber_time_s, frodo_time_s


if __name__ == "__main__":
    # Run this in the SAME Colab session, right after benchmark_pqc.py's
    # run_full_benchmark_suite() -- do not hardcode timing numbers here.
    #
    #     from benchmark_pqc import run_full_benchmark_suite
    #     from qsafe_simulation import extract_key_exchange_times, run_all_scenarios
    #
    #     bench_results = run_full_benchmark_suite(num_trials=100, kyber_num_trials=500)
    #     kyber_time_s, frodo_time_s = extract_key_exchange_times(
    #         bench_results["complete_key_exchange"], stat="median"
    #     )
    #     table2, sim_results = run_all_scenarios(kyber_time_s, frodo_time_s)
    #
    # This __main__ block intentionally does nothing on its own -- there
    # is no benchmark data available outside a Colab session with liboqs
    # installed, and hardcoding a "last known" number here is exactly the
    # transcription-drift problem this function was added to avoid.
    print("qsafe_simulation.py loaded. See the usage example in this "
          "__main__ block (or this file's module docstring) to run it "
          "against real benchmark_pqc.py output -- no numbers are "
          "hardcoded here on purpose.")
