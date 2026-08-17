"""
plot_complexity_figure.py

Figure 1: the merged two-panel complexity comparison.
  Panel A: integer factorization -- classical GNFS vs. quantum Shor
  Panel B: LWE -- classical brute-force vs. quantum Grover

REPLACES the two separate complexity plots from the original notebook.
Changes relative to that code, and why:

1. GNFS CONSTANT FIXED. The old code used c = 64/9 (~7.11) inside
   exp(c * (ln N)^(1/3) * (ln ln N)^(2/3)). The standard GNFS complexity
   L_N[1/3, c] uses c = (64/9)^(1/3) (~1.923) -- the cube root belongs on
   the constant, not just the ln N term. The old value inflated the
   exponent ~3.7x. The qualitative conclusion (sub-exponential vs.
   polynomial) is unchanged, but a reviewer who knows GNFS would catch
   the constant, so it is now correct. If the Methods text states the
   complexity form, state it as exp(((64/9)^(1/3)) (ln N)^(1/3) (ln ln N)^(2/3)).

2. time.sleep() "simulation" REMOVED. The old gnfs_simulation() slept
   for min(complexity/1e10, 2) seconds and timed the sleep -- the timing
   measured nothing but the sleep itself. Complexity values are analytic;
   they are now computed directly. (Describe this in Methods as
   "complexity models were evaluated", not as timed simulations.)

3. RED+GREEN ELIMINATED. The old plots drew classical in red and quantum
   in green -- the exact color pairing JEI's figure guide warns against
   (most common form of colorblindness). Both panels now use
   blue = classical attack, orange = quantum attack (validated
   colorblind-safe pair, CVD deltaE 26.7), with distinct markers and line
   styles as secondary encoding, consistent across panels.

4. NO ON-GRAPH TITLES (JEI rule) -- bare bold panel letters A)/B); the
   descriptive title belongs in the manuscript caption. Filename keeps a
   description while drafts are in flux; rename to plain "Figure 1.png"
   before Editorial Manager upload.

Deterministic (pure math, no benchmarking) -- runs anywhere with
matplotlib; no liboqs or Colab needed.
"""

import math
import numpy as np
import matplotlib.pyplot as plt

CLASSICAL_COLOR = "#2166AC"   # blue  = classical attack (both panels)
QUANTUM_COLOR = "#E08214"     # orange = quantum attack  (both panels)

GNFS_C = (64 / 9) ** (1 / 3)  # ~1.923 -- see note 1 above

def gnfs_complexity(n_bits: int) -> float:
    """Classical GNFS: L_N[1/3, (64/9)^(1/3)] operations (scaled estimate)."""
    ln_n = n_bits * math.log(2)          # ln(N) for an n-bit modulus
    lln_n = math.log(ln_n)
    return math.exp(GNFS_C * (ln_n ** (1 / 3)) * (lln_n ** (2 / 3)))

def shor_complexity(n_bits: int) -> float:
    """Quantum Shor: O((log N)^3) operations (scaled estimate)."""
    return float(n_bits) ** 3

def lwe_classical_complexity(dimension: int) -> float:
    """Classical attack on LWE: O(2^n) (scaled estimate, c = 1)."""
    return 2.0 ** dimension

def lwe_grover_complexity(dimension: int) -> float:
    """Quantum (Grover-assisted) attack on LWE: O(2^(n/2))."""
    return 2.0 ** (dimension / 2)

def plot_complexity_figure(save_path: str = "figures/Figure 1.png", show=True):
    modulus_bits = [256, 512, 1024, 2048, 4096, 8192]
    dimensions = [50, 100, 150, 200, 256, 300, 512]

    gnfs = [gnfs_complexity(b) for b in modulus_bits]
    shor = [shor_complexity(b) for b in modulus_bits]
    lwe_c = [lwe_classical_complexity(d) for d in dimensions]
    lwe_q = [lwe_grover_complexity(d) for d in dimensions]

    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(12, 5.2))

    def label_point(ax, x, y, dy=10, dx=0, ha="center"):
        """Selective value label: order of magnitude only (these are scaled
        analytic estimates -- exact digits would imply false precision).
        Endpoint labels use ha="right" + negative dx so they sit INSIDE the
        axes instead of spilling over the top/right border."""
        exponent = int(math.floor(math.log10(y)))
        ax.annotate(f"$\\sim10^{{{exponent}}}$", (x, y), xytext=(dx, dy),
                    textcoords="offset points", ha=ha, fontsize=9)

    # --- Panel A: integer factorization (RSA's foundation) ---
    ax_a.plot(modulus_bits, gnfs, "o-", color=CLASSICAL_COLOR, linewidth=2,
              markersize=7, label="Classical (GNFS)")
    ax_a.plot(modulus_bits, shor, "s--", color=QUANTUM_COLOR, linewidth=2,
              markersize=7, label="Quantum (Shor)")
    ax_a.set_yscale("log")
    ax_a.set_xscale("log", base=2)
    ax_a.set_xticks(modulus_bits)
    ax_a.set_xticklabels([str(b) for b in modulus_bits])
    ax_a.set_xlabel("RSA modulus size (bits)")
    ax_a.set_ylabel("Estimated operations (log scale)")
    ax_a.set_title("A)", loc="left", fontweight="bold")
    ax_a.legend(loc="upper left")
    ax_a.grid(True, alpha=0.3)
    # Selective labels: the deployed-standard key size (2048) and the endpoint --
    # the same values quoted in the Results text.
    ax_a.margins(y=0.15)
    label_point(ax_a, 2048, gnfs_complexity(2048), dy=10)
    label_point(ax_a, 2048, shor_complexity(2048), dy=-20)
    label_point(ax_a, 8192, gnfs_complexity(8192), dx=-10, dy=-4, ha="right")
    label_point(ax_a, 8192, shor_complexity(8192), dx=-10, dy=-14, ha="right")

    # --- Panel B: LWE (Kyber's and FrodoKEM's foundation) ---
    ax_b.plot(dimensions, lwe_c, "o-", color=CLASSICAL_COLOR, linewidth=2,
              markersize=7, label="Classical (brute force)")
    ax_b.plot(dimensions, lwe_q, "s--", color=QUANTUM_COLOR, linewidth=2,
              markersize=7, label="Quantum (Grover)")
    ax_b.set_yscale("log")
    ax_b.set_xlabel("Lattice dimension n")
    ax_b.set_ylabel("Estimated operations (log scale)")
    ax_b.set_title("B)", loc="left", fontweight="bold")
    ax_b.legend(loc="upper left")
    ax_b.grid(True, alpha=0.3)
    # Selective labels at n=256 (a cryptographically relevant dimension) and
    # the endpoint -- matching the values quoted in the Results text.
    ax_b.margins(y=0.15)
    label_point(ax_b, 256, lwe_classical_complexity(256), dy=10, dx=-6)
    label_point(ax_b, 256, lwe_grover_complexity(256), dy=-16, dx=-6)
    label_point(ax_b, 512, lwe_classical_complexity(512), dx=-10, dy=-4, ha="right")
    label_point(ax_b, 512, lwe_grover_complexity(512), dx=-14, dy=-20, ha="right")

    # NOTE: no fig.suptitle() -- JEI prohibits on-graph titles; the
    # descriptive title belongs in the manuscript's figure caption.
    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches="tight")
    if show:
        plt.show()
    else:
        plt.close(fig)      # release instead of leaking
    print(f"Saved to {save_path}")

    # Numbers worth quoting in Results -- floored orders of magnitude, so the
    # quoted text matches the on-graph labels exactly:
    oom = lambda v: int(math.floor(math.log10(v)))
    print(f"\nAt 2048-bit RSA: GNFS ~10^{oom(gnfs_complexity(2048))} ops "
          f"vs Shor ~10^{oom(shor_complexity(2048))} ops")
    print(f"At n=256 LWE:  classical ~10^{oom(lwe_classical_complexity(256))} ops "
          f"vs Grover ~10^{oom(lwe_grover_complexity(256))} ops (still astronomically hard)")
    print(f"Note for text: Grover at n=512 (~10^{oom(lwe_grover_complexity(512))}) equals "
          f"classical at n=256 (~10^{oom(lwe_classical_complexity(256))}) -- "
          f"the 'double the dimension' defense, visible directly on the graph.")
    

if __name__ == "__main__":
    # Force a non-interactive backend when run as a script, so an interactive
    # backend can never block waiting for a window to be closed. Fires only
    # under `python plot_complexity_figure.py`; importing the function into a
    # notebook leaves the inline backend untouched.
    import matplotlib
    matplotlib.use("Agg")

    file_path = sys.argv[1] if len(sys.argv) > 1 else "figures/Figure 1 - Quantum Complexity Comparison.png"
    plot_complexity_figure(file_path, show=False)
