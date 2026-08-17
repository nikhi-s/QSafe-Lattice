"""
benchmark_rsa.py

Benchmarks RSA key generation, encryption, and decryption across key sizes
and message sizes, and produces line-chart, heatmap, and multi-panel
scaling visualizations.

Fixes applied relative to the original benchmark-rsa.py (see git history /
project conversation log for full detail on each):
  1. Added the missing import of rsa_implementation functions (the old
     script called generate_rsa_key_pair/encrypt_message/etc. without
     importing them -> guaranteed NameError).
  2. Removed the double key-generation per trial (was: once for timing,
     once inside a memory-measurement call).
  3. Replaced the `lipsum` word-based message generator with
     os.urandom-based byte generation, sized exactly to message_size.
  4. Skip (key_size, message_size) combinations that exceed the RSA-OAEP
     plaintext ceiling *before* attempting encryption, with a clear log
     message, instead of silently getting None back from a caught
     exception.
  5. Fixed a broken plot_heatmaps() call whose arguments didn't match its
     own signature (guaranteed crash).
  6. Key generation is shared across message_sizes within each sample
     (one key per (sample, key_size), reused for every message_size),
     since keygen cost doesn't depend on message_size at all -- cuts
     RSA-8192's keygen count 7x for a 7-message_size sweep.
  7. Incremental checkpointing + resume support, so a Colab disconnect
     only costs the in-progress key size, and per-key-size sample count
     overrides (key_size_samples) for cases where measurement noise
     differs sharply by key size.
  8. Untimed warm-up call before the timed message_size loop, after
     discovering that the FIRST encrypt+decrypt call against any freshly
     generated key pays a one-time ~2x cost (likely OpenSSL lazily
     setting up Montgomery/blinding context on first use) -- this had
     been contaminating message_size=16 specifically in every sample.
  9. Key generation MEMORY measurement was removed entirely (not just
     unused) after verification showed both tracemalloc (sees ~24 bytes
     regardless of key size, since the real work happens in Rust/C via
     OpenSSL, outside Python's allocator) and process-level RSS-delta
     (confounded by allocator reuse, non-monotonic) were fundamentally
     broken, not just noisy. Memory usage was dropped from the paper
     entirely rather than publish either broken measurement -- see
     _benchmark_keygen()'s docstring for detail if this needs revisiting.
"""

import os
import time

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from rsa_implementation import (
    generate_rsa_key_pair,
    serialize_key,
    encrypt_message,
    decrypt_message,
    max_oaep_plaintext_bytes,
)

def _benchmark_keygen(key_size: int):
    """
    Generate one RSA key pair and time it. Split out from encryption/
    decryption benchmarking so the (expensive) keygen step can be run
    ONCE per (sample, key_size) and the resulting key reused across every
    message_size tested against it -- see collect_benchmark_data()
    docstring for why this matters.

    NOTE: this function previously also measured peak memory via
    tracemalloc. That was removed after verification showed it was
    fundamentally broken, not just noisy: tracemalloc only tracks
    Python-level heap allocations, but the `cryptography` library's
    actual RSA key generation (prime search, Miller-Rabin testing, CRT
    parameter computation) happens in Rust/C code calling into OpenSSL,
    entirely outside Python's allocator -- it reported ~24 bytes
    regardless of key size (1024 through 8192 bits). A process-level
    RSS-delta measurement was also tried and rejected (confounded by
    memory allocator reuse, producing a non-monotonic result where
    1024-bit appeared to use MORE memory than 2048/3072/4096-bit). Memory
    usage was subsequently dropped from the paper entirely rather than
    publish either broken measurement. If you need this later, it would
    require running each key size in an isolated subprocess and sampling
    RSS during execution, not before/after.
    """
    start_time = time.perf_counter()
    private_key, public_key = generate_rsa_key_pair(key_size)
    key_gen_time = time.perf_counter() - start_time

    start_time = time.perf_counter()
    serialize_key(private_key)
    serialization_time = time.perf_counter() - start_time
    serialize_key(public_key, is_private=False)

    return private_key, public_key, key_gen_time, serialization_time


def _benchmark_encrypt_decrypt(key_size: int, message_size: int, private_key, public_key):
    """
    Time encryption/decryption of a random message_size-byte message
    against an ALREADY-GENERATED key pair. Does not touch key generation.
    """
    result = {
        "encryption_time": None,
        "decryption_time": None,
        "ciphertext_size": None,
        "skipped_reason": None,
    }

    max_bytes = max_oaep_plaintext_bytes(key_size)
    if message_size > max_bytes:
        result["skipped_reason"] = (
            f"message_size={message_size}B exceeds RSA-OAEP/SHA-256 max "
            f"plaintext ({max_bytes}B) for a {key_size}-bit key"
        )
        return result

    message = os.urandom(message_size)
    try:
        start_time = time.perf_counter()
        encrypted_message = encrypt_message(message, public_key)
        result["encryption_time"] = time.perf_counter() - start_time
        result["ciphertext_size"] = len(encrypted_message)

        start_time = time.perf_counter()
        decrypted_message = decrypt_message(encrypted_message, private_key)
        result["decryption_time"] = time.perf_counter() - start_time

        assert decrypted_message == message, "Decryption did not round-trip!"
    except Exception as e:  # pragma: no cover - defensive logging path
        result["skipped_reason"] = f"unexpected error: {e}"

    return result


def benchmark_rsa(key_size: int, message_size: int):
    """
    Benchmark RSA key generation + encryption + decryption for a single
    (key_size, message_size) pair, generating a fresh key each call.

    Kept for standalone/ad-hoc use (e.g. testing one combination). For
    sweeping multiple message_sizes against the same key_size, use
    collect_benchmark_data() instead -- it reuses one key across all
    message_sizes per sample rather than paying keygen cost repeatedly.
    """
    private_key, public_key, key_gen_time, serialization_time = \
        _benchmark_keygen(key_size)
    result = _benchmark_encrypt_decrypt(key_size, message_size, private_key, public_key)
    result.update({
        "key_size": key_size,
        "message_size": message_size,
        "key_gen_time": key_gen_time,
        "serialization_time": serialization_time,
    })
    return result


def collect_benchmark_data(key_sizes, message_sizes, num_samples=10, key_size_samples=None,
                            checkpoint_path="rsa_benchmark_checkpoint.csv", resume=True):
    """
    Run the RSA benchmark across all (key_size, message_size) combinations
    and return a tidy DataFrame.

    KEY GENERATION IS SHARED ACROSS message_sizes WITHIN EACH SAMPLE: for
    each (sample_idx, key_size), ONE key pair is generated and reused for
    every message_size tested against it in that sample, since keygen cost
    does not depend on message_size at all.

    key_size_samples: optional dict overriding num_samples for specific
    key sizes, e.g. {1024: 500, 2048: 100}. Use this when relative noise in
    the timing measurements differs sharply by key size -- which it does
    here: RSA-1024's encryption time (a very fast, small-fixed-exponent
    operation) showed std/mean = 1.79 at n=10 (std larger than the mean,
    driven by a single scheduling-noise outlier), while 2048/3072/4096/
    8192-bit all showed a much tighter ~0.19-0.22. Recommended based on
    that measured noise: key_size_samples={1024: 500, 2048: 100}, leaving
    3072/4096/8192 at whatever num_samples you'd already planned (they're
    already precise enough at n=10; no need to pay extra keygen cost on
    the expensive 8192-bit case for a precision gain it doesn't need).
    Key sizes not present in this dict fall back to num_samples.

    INCREMENTAL CHECKPOINTING: after each (sample_idx, key_size) finishes
    (its keygen plus every message_size tested in that sample), results
    are immediately appended to `checkpoint_path`. This matters on Colab,
    where sessions can idle-disconnect (~90 min) or occasionally get
    preempted for resource reasons even mid-run.

    resume: if True (default) and checkpoint_path already exists from an
    earlier (possibly interrupted) call, already-completed
    (sample_idx, key_size) combinations are loaded from it and SKIPPED --
    the run continues from wherever it left off rather than starting
    over. Set resume=False to ignore/overwrite an existing checkpoint and
    start completely fresh. NOTE: if you change key_size_samples between
    runs (e.g. bumping 1024-bit from 10 to 500 after an initial run),
    resume will correctly add ONLY the new samples needed to reach the
    new target for each key size, not redo everything.
    """
    key_size_samples = key_size_samples or {}

    completed_combos = set()
    existing_rows = []
    if resume and os.path.exists(checkpoint_path):
        existing_df = pd.read_csv(checkpoint_path)
        existing_rows = existing_df.to_dict("records")
        completed_combos = set(zip(existing_df["sample_idx"], existing_df["key_size"]))
        print(f"[resume] Found checkpoint at {checkpoint_path}: {len(existing_rows)} rows "
              f"across {len(completed_combos)} completed (sample, key_size) combinations. "
              f"Skipping those and continuing.")
    elif not resume and os.path.exists(checkpoint_path):
        os.remove(checkpoint_path)
        print(f"[resume=False] Removed existing checkpoint at {checkpoint_path}; starting fresh.")

    results = list(existing_rows)
    total_combos = sum(key_size_samples.get(k, num_samples) for k in key_sizes)
    done_combos = len(completed_combos)

    for key_size in key_sizes:
        samples_for_this_key = key_size_samples.get(key_size, num_samples)
        for sample_idx in range(samples_for_this_key):
            if (sample_idx, key_size) in completed_combos:
                continue  # already benchmarked in a previous (interrupted) call

            private_key, public_key, key_gen_time, serialization_time = \
                _benchmark_keygen(key_size)

            # Untimed warm-up call, discarded from results. Confirmed via a
            # controlled test (holding message_size constant and varying
            # only call position after a fresh key) that the FIRST
            # encrypt+decrypt call against any freshly generated key pays
            # a one-time cost roughly 2x a steady-state call -- likely
            # OpenSSL lazily setting up Montgomery/blinding context on
            # first use, then caching it. Since message_sizes is iterated
            # in the same fixed order every time, this warm-up cost always
            # landed on message_size=16 specifically in every sample,
            # making it LOOK like a message-size effect when it was
            # actually a loop-position artifact. 16 bytes is used here
            # since it fits under every tested key size's OAEP ceiling.
            _benchmark_encrypt_decrypt(key_size, 16, private_key, public_key)

            combo_rows = []
            for message_size in message_sizes:
                result = _benchmark_encrypt_decrypt(key_size, message_size, private_key, public_key)
                result.update({
                    "key_size": key_size,
                    "message_size": message_size,
                    "sample_idx": sample_idx,
                    "key_gen_time": key_gen_time,
                    "serialization_time": serialization_time,
                })
                combo_rows.append(result)
                if result["skipped_reason"]:
                    print(
                        f"[skip] key_size={key_size} message_size={message_size}: "
                        f"{result['skipped_reason']}"
                    )

            results.extend(combo_rows)
            done_combos += 1

            # Write this (sample, key_size) combo's rows to the checkpoint
            # file immediately -- append if it already has content, create
            # with a header if this is the first write.
            combo_df = pd.DataFrame(combo_rows)
            write_header = not os.path.exists(checkpoint_path)
            combo_df.to_csv(checkpoint_path, mode="a", header=write_header, index=False)
            print(f"[checkpoint] sample {sample_idx}, key_size {key_size} bits done "
                  f"({done_combos}/{total_combos} combinations complete) -> saved to {checkpoint_path}")

    return pd.DataFrame(results)


def plot_rsa_summary(df, key_sizes, message_size=16, stat="median",
                       save_path="figures/Figure 2 - RSA Performance Scaling.png",
                       show_error_bars=True, error_bar_type="sem",show=True):
    """
    Combined multi-panel figure summarizing RSA performance across key
    sizes: key generation time, encryption time, decryption time, and
    ciphertext size.

    NOTE ON MEMORY USAGE: an earlier version of this function included a
    "key generation memory" panel using tracemalloc. That measurement was
    dropped after verification showed it was fundamentally broken, not
    just noisy: tracemalloc only tracks Python-level heap allocations, but
    the `cryptography` library's actual RSA key generation (prime search,
    Miller-Rabin testing, CRT parameter computation) happens in Rust/C
    code calling into OpenSSL, entirely outside Python's allocator --
    tracemalloc reported ~24 bytes regardless of key size (1024 through
    8192 bits), which is obviously not real. A process-level RSS-delta
    measurement was also tried and rejected: a single before/after
    snapshot in a long-running process is confounded by memory allocator
    reuse (the first, largest allocation grows the process heap, and
    later smaller allocations get satisfied from already-reserved-but-
    freed memory without RSS visibly increasing), producing a
    non-monotonic, unreliable result (1024-bit appeared to use MORE
    memory than 2048/3072/4096-bit). A trustworthy memory measurement
    would require running each key size in an isolated subprocess and
    sampling RSS during execution, not before/after -- not implemented
    here. If memory usage matters for your paper, do that properly rather
    than publishing either of the broken quick measurements above.

    Unlike plot_figure4() in plot_pqc_comparison.py (which compares TWO
    algorithms at matched security levels, where grouped bars make
    sense), this shows ONE algorithm (RSA) across ordered key sizes. A
    line plot with markers is used instead of bars, to show the SHAPE of
    the scaling behavior (e.g. decryption time growing much faster than
    encryption time as key size increases).

    message_size: which message size's rows to use (default 16, fits
    under every tested key size's OAEP ceiling). Time metrics are
    invariant to message size at a fixed key size anyway (RSA-OAEP always
    encrypts one full modulus-sized block).

    stat: "median" (default) or "mean" -- median is robust to the
    transient contention/throttling effects observed on shared cloud
    infrastructure (Colab); see collect_benchmark_data() docstring.

    show_error_bars: if True (default), draws error bars on the three
    timing panels (A/B/C), computed from the same underlying trial data
    used for the plotted statistic. Not drawn on panel D since ciphertext
    size is a fixed value, not sampled. JEI's own submission guidelines
    state: "For any data with replicates, data should be graphed with
    error bars" -- since every key size here has real replicates (n=500
    for 1024-bit, n=100 for the rest), this isn't optional polish, it's
    a stated requirement. Not drawn on panel D since ciphertext size is a
    fixed, non-sampled value.

    error_bar_type: "sem" (standard error of the mean, default -- matches
    the convention already used in plot_figure4() for the Kyber/FrodoKEM
    comparison) or "stdev" (raw sample spread, wider/more conservative).

    NOTE ON FILENAME: default save_path includes a description
    ("Figure 2 - RSA Performance Scaling.png") to keep working files
    identifiable while the manuscript's figure order is still in flux.
    JEI's own submission guidelines require the FINAL uploaded filename
    to be just "Figure 2.png" (no description) once the paper's figure
    numbering is locked in -- rename right before final upload.

    NOTE ON ON-GRAPH TITLE: JEI's guidelines explicitly prohibit titles
    on graphs themselves ("Please do not include titles on your graphs.
    Titles should be located in your figure captions and bolded.") --
    this function does NOT set a fig-level title/suptitle for that
    reason. Write the descriptive title in the manuscript's figure
    caption instead, not in code.
    """
    valid = df[(df["skipped_reason"].isna()) & (df["message_size"] == message_size)].copy()
    valid["encryption_time_ms"] = valid["encryption_time"] * 1000
    valid["decryption_time_ms"] = valid["decryption_time"] * 1000

    def sem(x):
        n = len(x)
        return x.std(ddof=1) / (n ** 0.5) if n > 1 else 0.0

    def stdev(x):
        return x.std(ddof=1) if len(x) > 1 else 0.0

    error_func = sem if error_bar_type == "sem" else stdev

    summary = valid.groupby("key_size").agg(
        key_gen_time_s=("key_gen_time", stat),
        key_gen_time_s_err=("key_gen_time", error_func),
        encryption_time_ms=("encryption_time_ms", stat),
        encryption_time_ms_err=("encryption_time_ms", error_func),
        decryption_time_ms=("decryption_time_ms", stat),
        decryption_time_ms_err=("decryption_time_ms", error_func),
        ciphertext_size_bytes=("ciphertext_size", "first"),
        n_samples=("encryption_time_ms", "count"),
    ).reindex(key_sizes)

    panels = [
        ("A", "key_gen_time_s", "Key Generation Time", "Time (seconds)", True),
        ("B", "encryption_time_ms", "Encryption Time", "Time (ms)", True),
        ("C", "decryption_time_ms", "Decryption Time", "Time (ms)", True),
        ("D", "ciphertext_size_bytes", "Ciphertext Size", "Size (bytes)", False),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(11, 9))
    axes = axes.flatten()
    color = "#2166AC"

    for ax, (label, col, title, ylabel, log_scale) in zip(axes, panels):
        x = summary.index.astype(str)
        y = summary[col]
        err_col = f"{col}_err"
        yerr = summary[err_col] if (show_error_bars and err_col in summary.columns) else None

        ax.errorbar(x, y, yerr=yerr, marker="o", color=color, linewidth=2, markersize=7,
                    capsize=5, elinewidth=1.4, capthick=1.4, ecolor="black")
        for xi, yi in zip(x, y):
            if pd.notna(yi):
                ax.annotate(f"{yi:.4g}", (xi, yi), xytext=(0, 8),
                            textcoords="offset points", ha="center", fontsize=8)
        ax.set_xlabel("Key size (bits)")
        ax.set_ylabel(ylabel)
        ax.set_title(f"{label}) {title}", loc="left", fontweight="bold")
        if log_scale:
            ax.set_yscale("log")
        ax.grid(True, alpha=0.3)

    # NOTE: no fig.suptitle() here -- JEI prohibits on-graph titles;
    # the descriptive title belongs in the figure caption (see docstring).
    plt.tight_layout()
    os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
    plt.savefig(save_path, dpi=200, bbox_inches="tight")
    if show:
        plt.show()
    else:
        plt.close(fig)      # release instead of leaking

    return summary

def plot_line_charts(df, key_sizes, metric, title, save_dir=".", stat="median", show=True):
    """
    Plot `metric` vs. message size, one line per key size.
 
    stat: "median" (default) or "mean". Defaults to median, not mean,
    because RSA encryption specifically is fast enough (sub-millisecond,
    small fixed public exponent) that a single scheduling-noise outlier
    can swing the mean substantially -- measured on real data, RSA-1024
    encryption showed std/mean = 1.79 (std LARGER than the mean) at
    n=10, driven by exactly one such outlier. Median is far more robust
    to this. This matches the convention already used for the Kyber/
    FrodoKEM comparison figures (plot_pqc_comparison.py).
 
    show: True displays the figure (notebook use); False closes it after
    saving, so a script neither leaks figures nor blocks on a window.
 
    Note the output filename is built from `metric`, not `title`:
    "{save_dir}/{metric}_line_chart.png".
 
    Rows where the metric is None (skipped combos, e.g. message too large
    for a given key's OAEP ceiling) are dropped automatically.
    """
    fig = plt.figure(figsize=(10, 6))
    for key_size in key_sizes:
        subset = df[df["key_size"] == key_size].dropna(subset=[metric])
        if subset.empty:
            continue
        grouped = subset.groupby("message_size")[metric].agg(stat).reset_index()
        plt.plot(
            grouped["message_size"],
            grouped[metric],
            marker="o",
            label=f"Key size: {key_size} bits",
        )
 
    # NOTE: no plt.title() -- JEI prohibits on-graph titles; put the
    # descriptive title in the figure caption if this is used in the paper.
    plt.xlabel("Message Size (bytes)")
    if "time" in metric:
        plt.ylabel("Time (seconds)")
    elif "memory" in metric:
        plt.ylabel("Memory (MB)")
    else:
        plt.ylabel("Size (bytes)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    os.makedirs(save_dir, exist_ok=True)
    plt.savefig(f"{save_dir}/{metric}_line_chart.png", dpi=200, bbox_inches="tight")
    if show:
        plt.show()
    else:
        plt.close(fig)      # release instead of leaking
 
 
def plot_heatmap(df, key_sizes, message_sizes, metric, title, save_dir=".",
                 colormap="viridis", stat="median", show=True):
    """
    Build a (key_size x message_size) matrix of `stat` metric values from
    the tidy DataFrame and plot it as a heatmap.
 
    stat: "median" (default) or "mean" -- see plot_line_charts() docstring
    for why median is the safer default given RSA-1024 encryption's
    measured noise (std/mean = 1.79 at n=10).
 
    show: see plot_line_charts().
    """
    pivot = (
        df.dropna(subset=[metric])
        .pivot_table(index="key_size", columns="message_size", values=metric, aggfunc=stat)
        .reindex(index=key_sizes, columns=message_sizes)
    )
    data = pivot.to_numpy()  # rows=key_sizes, cols=message_sizes; NaN where skipped/missing
 
    fig = plt.figure(figsize=(10, 8))
    plt.imshow(data, cmap=colormap, aspect="auto")
    plt.colorbar(label=title)
    plt.xticks(ticks=np.arange(len(message_sizes)), labels=[f"{m}B" for m in message_sizes],
               rotation=45, ha="right")
    plt.yticks(ticks=np.arange(len(key_sizes)), labels=[f"{k} bits" for k in key_sizes])
 
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            val = data[i, j]
            label = "N/A" if np.isnan(val) else f"{val:.2e}"
            plt.text(j, i, label, ha="center", va="center", fontsize=8, color="white")
 
    plt.xlabel("Message Size (bytes)")
    plt.ylabel("Key Size (bits)")
    # NOTE: no plt.title() -- JEI prohibits on-graph titles; put the
    # descriptive title in the figure caption if this is used in the paper.
    plt.tight_layout()
    os.makedirs(save_dir, exist_ok=True)
    plt.savefig(f"{save_dir}/{title.replace(' ', '_').lower()}.png", dpi=200, bbox_inches="tight")
    if show:
        plt.show()
    else:
        plt.close(fig)      # release instead of leaking
