"""
plot_pqc_comparison.py

Kyber vs. FrodoKEM comparison plots -- keygen/encap/decap time and
ciphertext size -- replacing the old plot_comparison() from the original
notebook.

WHAT CHANGED AND WHY:
The old version grouped bars by "message_length" ([1024, 2048, 4096]).
That's not meaningful for a KEM: encap_secret()/decap_secret() don't take
a plaintext message at all, so those three bars were three noisy samples
of the SAME operation mislabeled as if message size mattered (see
benchmark_pqc.py's docstring, point 2, for the full explanation).

The actual independent variable your paper compares Kyber and FrodoKEM
across is matched NIST security level -- this is exactly what Figure 4 in
your JEI draft already does (Kyber512/768/1024 vs.
FrodoKEM-640/976/1344-AES). So this version groups bars by security level
instead:

    Level 1: Kyber512   vs FrodoKEM-640-AES
    Level 3: Kyber768   vs FrodoKEM-976-AES
    Level 5: Kyber1024  vs FrodoKEM-1344-AES

It also reads from benchmark_pqc.py's actual output structure, where each
timing metric is a {"mean":.., "median":.., "stdev":..} dict from 100
trials (not a single raw sample per config, as in the old notebook).

Usage (after running benchmark_pqc.run_full_benchmark_suite() in Colab):

    from benchmark_pqc import run_full_benchmark_suite
    from plot_pqc_comparison import plot_all_comparisons

    results = run_full_benchmark_suite(num_trials=100)
    plot_all_comparisons(results["per_variant"], save_dir=".")
"""

import os

import numpy as np
import matplotlib.pyplot as plt

from pqc_config import FIGURE_DIR

# Single flat color per algorithm family. Previously this used a
# light-to-dark gradient across the three security levels, but that made
# the 2-entry legend ("Kyber", "FrodoKEM") inaccurate -- the legend swatch
# only shows the lightest shade, while two of the three bars per family
# are actually darker. Since the x-axis already labels the security level
# and every bar is annotated with its exact value, the color gradient was
# redundant information anyway; a flat color keeps the legend honest and
# simplifies the figure without losing anything a reader needs.
KYBER_COLOR = "#33A02C"   # Medium green
FRODO_COLOR = "#008B8B"   # Teal
# Kept for backward compatibility if you still want the gradient look in
# your own scripts; not used by default below.
KYBER_COLORS = ["#B2DF8A", "#33A02C", "#006400"]   # Light -> Dark Green
FRODO_COLORS = ["#A1D6E2", "#008B8B", "#004C4C"]   # Light Cyan -> Deep Teal

SECURITY_LEVELS = ["Level 1", "Level 3", "Level 5"]
KYBER_ALGS = ["Kyber512", "Kyber768", "Kyber1024"]
FRODO_ALGS = ["FrodoKEM-640-AES", "FrodoKEM-976-AES", "FrodoKEM-1344-AES"]


def _save(fig, save_path: str, dpi: int, show: bool):
    """Write a figure to disk, creating the folder if needed, then either
    display it or release it.

    matplotlib does NOT create a missing directory -- savefig raises
    FileNotFoundError. Since the default paths now point into figures/,
    every save goes through here. `or "."` covers a bare filename with no
    directory part. plt.close() on the non-display path stops a batch run
    from accumulating open figures until matplotlib warns."""
    os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
    plt.savefig(save_path, dpi=dpi, bbox_inches="tight")
    print(f"Saved to {save_path}")
    if show:
        plt.show()
    else:
        plt.close(fig)


def _extract(per_variant_results: dict, algs: list, metric_key: str, stat: str = "median"):
    """
    Pull one metric across the three security-level variants of one
    algorithm family.

    metric_key: "keygen_time_s" | "encap_time_s" | "decap_time_s"
                (each stored as {"mean":.., "median":.., "stdev":..})
                or "ciphertext_size_bytes" (a plain scalar, `stat` ignored).
    """
    values = []
    for alg in algs:
        entry = per_variant_results[alg][metric_key]
        values.append(entry[stat] if isinstance(entry, dict) else entry)
    return values


def plot_comparison(per_variant_results: dict, metric_key: str, title: str, ylabel: str,
                     log_scale: bool = False, stat: str = "median",
                     save_path: str = None, show: bool = True):
    """
    Grouped bar chart: Kyber vs. FrodoKEM, one pair of bars per matched
    NIST security level, for a single metric.
    """
    kyber_values = _extract(per_variant_results, KYBER_ALGS, metric_key, stat)
    frodo_values = _extract(per_variant_results, FRODO_ALGS, metric_key, stat)

    x = np.arange(len(SECURITY_LEVELS))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 6))
    kyber_bars = ax.bar(x - width / 2, kyber_values, width,
                         label="Kyber", color=KYBER_COLOR, edgecolor="black")
    frodo_bars = ax.bar(x + width / 2, frodo_values, width,
                         label="FrodoKEM", color=FRODO_COLOR, edgecolor="black")

    # Label each bar with its specific variant name (e.g. "Kyber512",
    # "976") so the security-level grouping doesn't lose that detail.
    for bar, alg in zip(kyber_bars, KYBER_ALGS):
        ax.annotate(alg, (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8)
    for bar, alg in zip(frodo_bars, FRODO_ALGS):
        label = alg.replace("FrodoKEM-", "").replace("-AES", "")
        ax.annotate(label, (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(SECURITY_LEVELS)
    ax.set_xlabel("NIST Security Level")
    ax.set_ylabel(ylabel)
    # NOTE: no ax.set_title() -- JEI prohibits on-graph titles; put the
    # descriptive title in the figure caption if this is used in the paper.
    ax.legend()
    if log_scale:
        ax.set_yscale("log")
    ax.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    if save_path:
        _save(fig, save_path, dpi=150, show=show)
    elif show:
        plt.show()
    else:
        plt.close(fig)


def _format_bar_value(value, metric_key: str) -> str:
    """
    Format the value printed above a bar. Time metrics auto-scale between
    microseconds and milliseconds for readability (Kyber operations are
    tens of microseconds; FrodoKEM operations are single-digit
    milliseconds -- a single fixed unit would make one family's labels
    hard to read). Ciphertext size is shown as a plain byte count.
    """
    if metric_key == "ciphertext_size_bytes":
        return f"{int(round(value))} B"
    # time metric, value is in seconds
    if value < 1e-3:
        return f"{value * 1e6:.1f} \u03bcs"
    return f"{value * 1e3:.2f} ms"


def plot_figure4(per_variant_results: dict, stat: str = "median",
                  save_path: str = os.path.join(
                      FIGURE_DIR, "Figure 3 - Kyber vs FrodoKEM Performance.png"),
                  show_error_bars: bool = True, error_bar_type: str = "sem",
                  annotate_values: bool = True, color_style: str = "flat",
                  show: bool = True):
    """
    Combined 2x2 panel matching the JEI draft's Figure 4 caption exactly:
    "A) Encapsulation time, B) decapsulation time, C) key generation time
    (all log scale, seconds), and D) ciphertext size (bytes)."

    stat: "median" (default, matches the project's chosen convention of
    reporting mean/median rather than min) or "mean" or "min". For fast
    operations (Kyber, tens of microseconds), system noise only ever ADDS
    delay, so `min` can be a cleaner estimate of true cost -- but this
    project uses median/mean throughout for consistency with the stated
    Methods text, so that's the default here too.

    error_bar_type: "sem" (standard error of the mean, stdev/sqrt(n) --
    reflects how precisely the statistic is pinned down) or "stdev" (raw
    sample spread). SEM is tighter and generally more appropriate for a
    published figure; stdev is more conservative/pessimistic-looking.
    Not applicable when stat="min" (no natural error bar for a minimum);
    error bars are automatically suppressed in that case.

    IMPORTANT -- if stat="median" and error_bar_type="sem" (as used for
    the version reviewed in the paper), say so explicitly in the Methods
    section: "Timing values are reported as the median of N trials, with
    error bars showing the standard error of the mean (SEM)." This is a
    specific, citable methodological choice -- don't leave it implicit.
    Note the RSA benchmarks (benchmark_rsa.plot_rsa_summary and
    generate_rsa_table_and_figure) use the SAME median + SEM convention,
    so the whole paper is internally consistent -- keep it that way if
    either side ever changes.

    show_error_bars: if True, draws error bars on the three timing panels
    (A/B/C). Not drawn on panel D since ciphertext size is a fixed value,
    not sampled. Also suppressed automatically when stat="min".

    annotate_values: if True, prints the actual measured value above each
    bar (auto-scaled microseconds/milliseconds for time panels, bytes for
    ciphertext size) -- the standard convention for bar charts, since it
    lets a reader read off the precise number without eyeballing a
    log-scale axis. Replaces an earlier version of this function that
    printed the algorithm variant name instead, which was redundant with
    the legend/color coding and gave no additional information.

    color_style: "flat" (default) uses one color per algorithm family and
    a 2-entry legend (Kyber, FrodoKEM) that exactly matches what's on
    screen. "gradient" restores the light-to-dark shading across security
    levels and expands the legend to 6 entries (one per specific variant,
    e.g. "Kyber-512", "FrodoKEM-976") so the legend stays accurate to the
    actual bar colors. Both are legitimate choices -- "flat" is more
    compact since the x-axis and per-bar value labels already identify
    the security level; "gradient" adds a visual family/progression cue
    at the cost of a busier legend.
    """
    panels = [
        ("A", "encap_time_s", "Encapsulation Time", "Time (seconds)", True),
        ("B", "decap_time_s", "Decapsulation Time", "Time (seconds)", True),
        ("C", "keygen_time_s", "Key Generation Time", "Time (seconds)", True),
        ("D", "ciphertext_size_bytes", "Ciphertext Size", "Size (bytes)", False),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(13, 10))
    axes = axes.flatten()
    x = np.arange(len(SECURITY_LEVELS))
    width = 0.35
    draw_error_bars = show_error_bars and stat != "min"
    use_gradient = color_style == "gradient"
    # Bumped from the original capsize=4 with no explicit line width -- at
    # the original setting, error bars were nearly invisible against the
    # bar outlines on a printed/reviewed figure. This is purely cosmetic;
    # it does not change any reported value.
    error_kw = {"capsize": 7, "elinewidth": 1.6, "capthick": 1.6, "ecolor": "black"}

    legend_handles = None
    for ax, (label, metric_key, title, ylabel, log_scale) in zip(axes, panels):
        kyber_values = _extract(per_variant_results, KYBER_ALGS, metric_key, stat)
        frodo_values = _extract(per_variant_results, FRODO_ALGS, metric_key, stat)

        kyber_err = frodo_err = None
        if draw_error_bars and metric_key != "ciphertext_size_bytes":
            kyber_err = [per_variant_results[a][metric_key][error_bar_type] for a in KYBER_ALGS]
            frodo_err = [per_variant_results[a][metric_key][error_bar_type] for a in FRODO_ALGS]

        kyber_bar_colors = KYBER_COLORS if use_gradient else KYBER_COLOR
        frodo_bar_colors = FRODO_COLORS if use_gradient else FRODO_COLOR
        kyber_bars = ax.bar(x - width / 2, kyber_values, width, yerr=kyber_err,
                             label="Kyber", color=kyber_bar_colors, edgecolor="black",
                             error_kw=error_kw if kyber_err else None)
        frodo_bars = ax.bar(x + width / 2, frodo_values, width, yerr=frodo_err,
                             label="FrodoKEM", color=frodo_bar_colors, edgecolor="black",
                             error_kw=error_kw if frodo_err else None)
        if legend_handles is None:
            legend_handles = (kyber_bars, frodo_bars)

        if annotate_values:
            for bar, value in zip(kyber_bars, kyber_values):
                ax.annotate(_format_bar_value(value, metric_key),
                            (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                            xytext=(0, 3), textcoords="offset points", ha="center", fontsize=7.5)
            for bar, value in zip(frodo_bars, frodo_values):
                ax.annotate(_format_bar_value(value, metric_key),
                            (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                            xytext=(0, 3), textcoords="offset points", ha="center", fontsize=7.5)

        ax.set_xticks(x)
        ax.set_xticklabels(SECURITY_LEVELS)
        ax.set_ylabel(ylabel)
        ax.set_title(f"{label}) {title}", loc="left", fontweight="bold")
        if log_scale:
            ax.set_yscale("log")
        ax.grid(True, axis="y", alpha=0.3)
        # Give annotated bar labels room so they don't get clipped at the
        # top of the axes, especially on log-scaled panels.
        if annotate_values:
            ax.margins(y=0.15)

    if use_gradient:
        from matplotlib.patches import Patch
        legend_patches = (
            [Patch(facecolor=c, edgecolor="black", label=f"Kyber-{n.replace('Kyber', '')}")
             for c, n in zip(KYBER_COLORS, KYBER_ALGS)]
            + [Patch(facecolor=c, edgecolor="black",
                     label=f"FrodoKEM-{n.replace('FrodoKEM-', '').replace('-AES', '')}")
               for c, n in zip(FRODO_COLORS, FRODO_ALGS)]
        )
        fig.legend(handles=legend_patches, loc="lower center", ncol=2,
                   bbox_to_anchor=(0.5, -0.08), frameon=False)
    else:
        fig.legend(legend_handles, ["Kyber", "FrodoKEM"], loc="lower center",
                   ncol=2, bbox_to_anchor=(0.5, -0.02), frameon=False)
    # NOTE: no fig.suptitle() -- JEI prohibits on-graph titles; the
    # descriptive title belongs in the manuscript's figure caption.
    #
    # NOTE ON FILENAME: default save_path includes a description
    # ("Figure 3 - Kyber vs FrodoKEM Performance.png") to keep working
    # files identifiable while the manuscript's figure order is still in
    # flux. JEI requires the FINAL uploaded filename to be just
    # "Figure 3.png" (no description) -- rename right before final upload.
    plt.tight_layout(rect=[0, 0.08 if use_gradient else 0.03, 1, 0.97])
    _save(fig, save_path, dpi=200, show=show)

    if draw_error_bars:
        kyber_n = per_variant_results.get(KYBER_ALGS[0], {}).get("num_trials")
        frodo_n = per_variant_results.get(FRODO_ALGS[0], {}).get("num_trials")
        if kyber_n is not None and frodo_n is not None and kyber_n != frodo_n:
            trial_str = f"{kyber_n} trials (Kyber), {frodo_n} trials (FrodoKEM)"
        elif kyber_n is not None:
            trial_str = f"{kyber_n} trials"
        else:
            trial_str = "N trials (num_trials not found in results -- check benchmark_pqc.py output)"
        print(f"NOTE for Methods section: bars show {stat} of {trial_str}; error bars show "
              f"{'standard error of the mean (SEM)' if error_bar_type == 'sem' else 'standard deviation (raw sample spread)'}. "
              f"State this explicitly in the manuscript -- see this function's docstring.")


def plot_all_comparisons(per_variant_results: dict, stat: str = "median",
                          save_dir: str = FIGURE_DIR, show: bool = True):
    """
    Generate the four standard Kyber-vs-FrodoKEM comparison plots
    (keygen time, encap time, decap time, ciphertext size), matching what
    Figure 4 in the JEI draft describes.
    """
    def path(name):
        return f"{save_dir}/{name}.png" if save_dir else None

    plot_comparison(per_variant_results, "keygen_time_s",
                     "Key Generation Time (Kyber vs. FrodoKEM)", "Time (seconds)",
                     log_scale=True, stat=stat, save_path=path("keygen_time_comparison"), show=show)
    plot_comparison(per_variant_results, "encap_time_s",
                     "Encapsulation Time (Kyber vs. FrodoKEM)", "Time (seconds)",
                     log_scale=True, stat=stat, save_path=path("encap_time_comparison"), show=show)
    plot_comparison(per_variant_results, "decap_time_s",
                     "Decapsulation Time (Kyber vs. FrodoKEM)", "Time (seconds)",
                     log_scale=True, stat=stat, save_path=path("decap_time_comparison"), show=show)
    plot_comparison(per_variant_results, "ciphertext_size_bytes",
                     "Ciphertext Size (Kyber vs. FrodoKEM)", "Size (bytes)",
                     log_scale=False, stat=stat, save_path=path("ciphertext_size_comparison"), show=show)


# No __main__ block / smoke test here on purpose. This module only produces
# meaningful plots from REAL benchmark_pqc.run_full_benchmark_suite() output.
# Usage, after running that in Colab:
#
#     from benchmark_pqc import run_full_benchmark_suite
#     from plot_pqc_comparison import plot_figure4, plot_all_comparisons
#
#     results = run_full_benchmark_suite(num_trials=100, kyber_num_trials=500)
#     plot_figure4(results["per_variant"], save_path="figure4.png")       # for the paper
#     plot_all_comparisons(results["per_variant"], save_dir=".")          # for exploring
