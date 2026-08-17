"""
generate_rsa_table_and_figure.py

Produces the final RSA Table 1 (CSV + markdown, ready to paste into the
manuscript) and the 4-panel RSA scaling figure (Figure 3), both from the
same verified benchmark_rsa.py output -- so the numbers in the table and
the numbers in the figure are guaranteed to match, since they come from
one function reading one source file.

Usage in Colab, after collect_benchmark_data() has produced your CSV:

    from generate_rsa_table_and_figure import generate_table_and_figure
    table, fig_summary = generate_table_and_figure("rsa_benchmark_results.csv")

Or from the command line:

    python generate_rsa_table_and_figure.py rsa_benchmark_results.csv
"""

import sys, os
import pandas as pd

from benchmark_rsa import plot_rsa_summary


def generate_table_and_figure(csv_path: str, key_sizes=None, message_size: int = 16,
                                stat: str = "median", error_bar_type: str = "sem",
                                table_csv_path: str = "Table 1 - RSA Performance Summary.csv",
                                figure_path: str = "figures/Figure 2 - RSA Performance Scaling.png"):
    """
    Load benchmark_rsa.py's output CSV and produce:
      1. Table 1 (CSV + markdown) -- the final numbers, including the same
         uncertainty (SEM/stdev) shown in Figure 2's error bars, so the
         table and figure report matching information, not just matching
         point estimates.
      2. Figure 2 -- the 4-panel scaling figure (keygen time, encryption
         time, decryption time, ciphertext size vs. key size), with error
         bars on the three timing panels.

    NOTE ON FILENAMES: defaults include descriptions ("Table 1 - RSA
    Performance Summary.csv", "Figure 2 - RSA Performance Scaling.png")
    to keep working files identifiable while the manuscript's figure/
    table order is still in flux -- strip the description before final
    JEI submission (figures must be uploaded as exactly "Figure 2.png",
    etc.; tables are pasted into the manuscript as editable Word tables,
    so the CSV filename itself doesn't matter to JEI, only kept
    descriptive here for your own organization).

    IMPORTANT: figure_path here MUST be kept in sync with whatever
    plot_rsa_summary()'s own default save_path is in benchmark_rsa.py --
    this function's figure_path argument overrides that default when
    passed through below. If you rename Figure 2 in one file, rename it
    in both, or the two will drift apart silently.

    key_sizes: which key sizes to include, in display order (default: all
    key sizes present in the CSV, sorted ascending).

    message_size: which message size's rows to use for the table/figure
    (default 16 bytes, since it's valid across every commonly tested key
    size's OAEP/SHA-256 ceiling -- see rsa_implementation.py). Encryption/
    decryption time is invariant to message size at a fixed key size
    anyway (RSA-OAEP always encrypts one full modulus-sized block), so
    this choice only affects which rows get selected, not the results.

    stat: "median" (default) or "mean". Median is used throughout this
    project because it's robust to transient timing noise/contention
    observed on shared cloud infrastructure (Colab) -- see
    collect_benchmark_data()'s docstring for the measured evidence.

    error_bar_type: "sem" (default) or "stdev" -- must match what you pass
    to plot_rsa_summary()/Figure 3, or the table and figure will report
    different uncertainty for the same numbers.

    Returns (table_df, figure_summary_df) -- both should be numerically
    identical for the shared columns; figure_summary_df is what
    plot_rsa_summary() itself computed and plotted, included here so you
    can double-check the table and the figure agree.
    """
    df = pd.read_csv(csv_path)

    if key_sizes is None:
        key_sizes = sorted(df["key_size"].unique().tolist())

    valid = df[(df["skipped_reason"].isna()) & (df["message_size"] == message_size)].copy()
    valid["encryption_time_ms"] = valid["encryption_time"] * 1000
    valid["decryption_time_ms"] = valid["decryption_time"] * 1000

    def sem(x):
        n = len(x)
        return x.std(ddof=1) / (n ** 0.5) if n > 1 else 0.0

    def stdev(x):
        return x.std(ddof=1) if len(x) > 1 else 0.0

    error_func = sem if error_bar_type == "sem" else stdev
    err_label = error_bar_type  # "sem" or "stdev", used in column names

    table = valid.groupby("key_size").agg(
        n_samples=("encryption_time_ms", "count"),
        key_gen_time_s=("key_gen_time", stat),
        **{f"key_gen_time_s_{err_label}": ("key_gen_time", error_func)},
        encryption_time_ms=("encryption_time_ms", stat),
        **{f"encryption_time_ms_{err_label}": ("encryption_time_ms", error_func)},
        decryption_time_ms=("decryption_time_ms", stat),
        **{f"decryption_time_ms_{err_label}": ("decryption_time_ms", error_func)},
        ciphertext_size_bytes=("ciphertext_size", "first"),
    ).reindex(key_sizes).round(5)

    table.to_csv(table_csv_path)
    print(f"Table saved to {table_csv_path}\n")
    print(table.to_string())
    print()
    print("--- Markdown (paste into manuscript) ---")
    print(table.to_markdown())
    print()

    print(f"Generating figure (message_size={message_size}B, stat={stat}, error_bar_type={error_bar_type})...")
    os.makedirs(os.path.dirname(figure_path) or ".", exist_ok=True)
    figure_summary = plot_rsa_summary(df, key_sizes=key_sizes, message_size=message_size,
                                        stat=stat, error_bar_type=error_bar_type, save_path=figure_path)
    print(f"Figure saved to {figure_path}")

    # Sanity check: table and figure should report identical numbers,
    # including the error/uncertainty columns, since both are computed
    # from the same underlying data with the same stat/error_bar_type.
    # If they disagree, something is wrong.
    shared_cols = ["key_gen_time_s", "encryption_time_ms", "decryption_time_ms",
                   "ciphertext_size_bytes"]
    err_cols_table_to_fig = {
        f"key_gen_time_s_{err_label}": "key_gen_time_s_err",
        f"encryption_time_ms_{err_label}": "encryption_time_ms_err",
        f"decryption_time_ms_{err_label}": "decryption_time_ms_err",
    }
    mismatch = False
    for col in shared_cols:
        table_vals = table[col].values
        fig_vals = figure_summary[col].round(5).values
        if not (pd.Series(table_vals).fillna(-1).round(5) == pd.Series(fig_vals).fillna(-1)).all():
            print(f"WARNING: mismatch between table and figure in column '{col}' -- investigate before using either.")
            mismatch = True
    for table_col, fig_col in err_cols_table_to_fig.items():
        table_vals = table[table_col].values
        fig_vals = figure_summary[fig_col].round(5).values
        if not (pd.Series(table_vals).fillna(-1).round(5) == pd.Series(fig_vals).fillna(-1)).all():
            print(f"WARNING: mismatch between table and figure in error column '{table_col}' -- investigate before using either.")
            mismatch = True
    if not mismatch:
        print("Table and figure numbers (including error bars) verified consistent.")

    return table, figure_summary

if __name__ == "__main__":
    # Force a non-interactive backend when run as a script, so an interactive
    # backend can never block waiting for a window to be closed. Fires only
    # under `python generate_table_and_figure.py`; importing the function into a
    # notebook leaves the inline backend untouched.
    import matplotlib
    matplotlib.use("Agg")

    csv_path = sys.argv[1] if len(sys.argv) > 1 else "rsa_benchmark_results.csv"
    generate_table_and_figure(csv_path, show=False)
