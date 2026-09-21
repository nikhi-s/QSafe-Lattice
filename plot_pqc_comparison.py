"""
plot_pqc_comparison.py

Kyber vs. FrodoKEM comparison plots -- keygen/encap/decap time and
ciphertext size -- replacing the old plot_comparison() from the original
notebook.
"""

import os

import numpy as np
import matplotlib.pyplot as plt

from pqc_config import FIGURE_DIR, KYBER_ALGS, FRODO_ALGS

# Single flat color per algorithm family.
KYBER_COLOR = "#33A02C"   # Medium green
FRODO_COLOR = "#008B8B"   # Teal
KYBER_COLORS = ["#B2DF8A", "#33A02C", "#006400"]   # Light -> Dark Green
FRODO_COLORS = ["#A1D6E2", "#008B8B", "#004C4C"]   # Light Cyan -> Deep Teal

SECURITY_LEVELS = ["Level 1", "Level 3", "Level 5"]


def _save(fig, save_path: str, dpi: int, show: bool):
    """Write a figure to disk, creating the folder if needed."""
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
    """Format the value printed above a bar."""
    if metric_key == "ciphertext_size_bytes":
        return f"{int(round(value))} B"
    if value < 1e-3:
        return f"{value * 1e6:.1f} \u03bcs"
    return f"{value * 1e3:.2f} ms"


def plot_kem_comparison_panels(per_variant_results: dict, stat: str = "median",
                  save_path: str = os.path.join(
                      FIGURE_DIR, "Figure 3 - Kyber vs FrodoKEM Performance.png"),
                  show_error_bars: bool = True, error_bar_type: str = "sem",
                  annotate_values: bool = True, color_style: str = "flat",
                  show: bool = True):
    """
    Combined 2x2 panel comparing Kyber and FrodoKEM at matched NIST
    security levels: encapsulation, decapsulation, key generation, and
    ciphertext size.
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
        ax.set_title(f"{label})", loc="left", fontweight="bold")
        if log_scale:
            ax.set_yscale("log")
        ax.grid(True, axis="y", alpha=0.3)
        if annotate_values:
            ax.margins(y=0.15)

    if use_gradient:
        from matplotlib.patches import Patch
        legend_patches = (
            [Patch(facecolor=c, edgecolor="black", label=n)
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

    plt.tight_layout(rect=[0, 0.08 if use_gradient else 0.03, 1, 0.97])
    _save(fig, save_path, dpi=200, show=show)


def plot_all_comparisons(per_variant_results: dict, stat: str = "median",
                          save_dir: str = FIGURE_DIR, show: bool = True):
    """Generate all standard Kyber vs FrodoKEM comparison plots."""
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
