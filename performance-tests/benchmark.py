#!/usr/bin/env python3
"""Time ML-KEM and the legacy Kyber classes, then draw the charts in the README.

Run it against a release build, because a debug build is many times slower:

    maturin develop --release
    python performance-tests/benchmark.py

It writes results.json, latency.png and ml_kem_vs_kyber.png next to itself and
prints the table that the README shows. Needs matplotlib (see requirements-dev.txt).
"""

import json
import platform
import statistics
import sys
import time
import warnings
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

import pykyber  # noqa: E402

HERE = Path(__file__).resolve().parent

# Each round times ITERATIONS calls and the median of ROUNDS rounds is reported,
# so one slow round (a scheduler hiccup, a frequency change) does not decide the number.
ITERATIONS = 500
ROUNDS = 7
WARMUP_CALLS = 200

LEVELS = ("512", "768", "1024")
OPERATIONS = ("keypair", "encapsulate", "decapsulate")
OPERATION_LABELS = {
    "keypair": "Key generation",
    "encapsulate": "Encapsulation",
    "decapsulate": "Decapsulation",
}
FAMILIES = {"ML-KEM": "ML_KEM_{}", "Kyber": "Kyber{}"}

NS_PER_MS = 1_000_000
MS_PER_S = 1_000

# Okabe-Ito blue, vermillion and green. They pass scripts/validate_palette.js from the
# dataviz skill on a white surface (colour-blind separation and 3:1 contrast).
OPERATION_COLORS = {"keypair": "#0072B2", "encapsulate": "#D55E00", "decapsulate": "#009E73"}
INK = "#1f2328"
MUTED = "#59636e"
GRID = "#d1d9e0"
DPI = 150
# Opacity of the Kyber bars, so they read as the secondary series next to ML-KEM.
KYBER_ALPHA = 0.45


def time_rounds(call):
    """Milliseconds per call for each round."""
    for _ in range(WARMUP_CALLS):
        call()
    rounds = []
    for _ in range(ROUNDS):
        start = time.perf_counter_ns()
        for _ in range(ITERATIONS):
            call()
        rounds.append((time.perf_counter_ns() - start) / ITERATIONS / NS_PER_MS)
    return rounds


def bench_class(cls):
    """Time one class through its public API, with static calls for the receiver steps."""
    keypair = cls()
    public_key = keypair.public_key
    secret_key = keypair.secret_key
    ciphertext = cls.encapsulate(public_key).ciphertext
    calls = {
        "keypair": lambda: cls(),
        "encapsulate": lambda: cls.encapsulate(public_key),
        "decapsulate": lambda: cls.decapsulate(ciphertext, secret_key),
    }
    return {op: time_rounds(calls[op]) for op in OPERATIONS}


def run():
    results = {}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # the Kyber classes warn once per process
        for pattern in FAMILIES.values():
            for level in LEVELS:
                name = pattern.format(level)
                print(f"timing {name} ...", flush=True)
                rounds = bench_class(getattr(pykyber, name))
                results[name] = {
                    op: {
                        "median_ms": statistics.median(values),
                        "min_ms": min(values),
                        "max_ms": max(values),
                    }
                    for op, values in rounds.items()
                }
    return results


def machine_info():
    cpu = platform.processor() or platform.machine()
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {
        "cpu": cpu,
        "os": platform.platform(),
        "python": platform.python_version(),
        "iterations": ITERATIONS,
        "rounds": ROUNDS,
    }


def footnote(info):
    return (
        f"{info['cpu']}, Python {info['python']}, release build. "
        f"Median of {info['rounds']} rounds of {info['iterations']} calls."
    )


def style(ax):
    ax.set_facecolor("white")
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=MUTED, length=0)


def latency_chart(results, info):
    """Time per call for the three ML-KEM sets, one bar per operation."""
    names = [f"ML_KEM_{level}" for level in LEVELS]
    fig, ax = plt.subplots(figsize=(9, 5), facecolor="white")
    style(ax)
    width = 0.26
    gap = 0.02
    for j, op in enumerate(OPERATIONS):
        xs = [i + (j - 1) * (width + gap) for i in range(len(names))]
        medians = [results[n][op]["median_ms"] for n in names]
        below = [results[n][op]["median_ms"] - results[n][op]["min_ms"] for n in names]
        above = [results[n][op]["max_ms"] - results[n][op]["median_ms"] for n in names]
        bars = ax.bar(xs, medians, width, color=OPERATION_COLORS[op], label=OPERATION_LABELS[op])
        ax.errorbar(xs, medians, yerr=[below, above], fmt="none", ecolor=INK, elinewidth=1, capsize=3)
        for bar, value, top in zip(bars, medians, (results[n][op]["max_ms"] for n in names)):
            # Label above the whisker, so the number never sits on the line.
            ax.annotate(f"{value:.3f}", (bar.get_x() + bar.get_width() / 2, top),
                        xytext=(0, 4), textcoords="offset points", ha="center",
                        fontsize=8, color=INK)
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels([f"ML-KEM-{level}" for level in LEVELS], color=INK, fontsize=11)
    ax.set_ylabel("milliseconds per call (lower is faster)", color=MUTED)
    ax.set_title("ML-KEM time per operation", loc="left", color=INK, fontsize=14,
                 fontweight="bold")
    ax.legend(frameon=False, loc="upper left", labelcolor=INK)
    fig.text(0.01, 0.01, footnote(info) + " Whiskers show the fastest and slowest round.",
             fontsize=7, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(HERE / "latency.png", dpi=DPI, facecolor="white")
    plt.close(fig)


def comparison_chart(results, info):
    """Operations per second, ML-KEM against the deprecated Kyber classes."""
    fig, axes = plt.subplots(1, 3, figsize=(12, 4.8), facecolor="white")
    width = 0.36
    gap = 0.02
    for ax, op in zip(axes, OPERATIONS):
        style(ax)
        for j, (family, pattern) in enumerate(FAMILIES.items()):
            xs = [i + (j - 0.5) * (width + gap) for i in range(len(LEVELS))]
            rates = [MS_PER_S / results[pattern.format(level)][op]["median_ms"] for level in LEVELS]
            is_kyber = family == "Kyber"
            bars = ax.bar(xs, rates, width, color=OPERATION_COLORS[op],
                          alpha=KYBER_ALPHA if is_kyber else 1.0,
                          hatch="///" if is_kyber else "", edgecolor="white", linewidth=0)
            for bar, value in zip(bars, rates):
                ax.annotate(f"{value:,.0f}", (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                            xytext=(0, 4), textcoords="offset points", ha="center",
                            fontsize=7.5, color=INK)
        ax.set_xticks(range(len(LEVELS)))
        ax.set_xticklabels(LEVELS, color=INK)
        ax.set_title(OPERATION_LABELS[op], loc="left", color=INK, fontsize=12, fontweight="bold")
    axes[0].set_ylabel("operations per second (higher is faster)", color=MUTED)
    handles = [
        plt.Rectangle((0, 0), 1, 1, facecolor=MUTED),
        plt.Rectangle((0, 0), 1, 1, facecolor=MUTED, alpha=KYBER_ALPHA, hatch="///",
                      edgecolor="white"),
    ]
    fig.legend(handles, ["ML-KEM (solid)", "Kyber, deprecated (hatched)"], frameon=False,
               loc="upper right", labelcolor=INK, ncol=2)
    fig.suptitle("ML-KEM and the legacy Kyber classes", x=0.01, ha="left", color=INK,
                 fontsize=14, fontweight="bold")
    fig.text(0.01, 0.01, footnote(info) + " Axis labels are the parameter set (512, 768, 1024).",
             fontsize=7, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 0.94))
    fig.savefig(HERE / "ml_kem_vs_kyber.png", dpi=DPI, facecolor="white")
    plt.close(fig)


def markdown_table(results):
    lines = [
        "| Class | Key generation | Encapsulation | Decapsulation |",
        "|-------|----------------|---------------|---------------|",
    ]
    for family, pattern in FAMILIES.items():
        for level in LEVELS:
            name = pattern.format(level)
            cells = []
            for op in OPERATIONS:
                ms = results[name][op]["median_ms"]
                cells.append(f"{ms:.3f} ms ({MS_PER_S / ms:,.0f}/s)")
            label = f"`ML_KEM_{level}`" if family == "ML-KEM" else f"`Kyber{level}`"
            lines.append(f"| {label} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main():
    if not hasattr(pykyber, "ML_KEM_768"):
        sys.exit("this pykyber build has no ML-KEM; build the 2.0 branch with maturin develop --release")
    info = machine_info()
    results = run()
    (HERE / "results.json").write_text(
        json.dumps({"machine": info, "results": results}, indent=2) + "\n", encoding="ascii"
    )
    latency_chart(results, info)
    comparison_chart(results, info)
    print()
    print(footnote(info))
    print()
    print(markdown_table(results))
    print("\nWrote results.json, latency.png and ml_kem_vs_kyber.png in", HERE)


if __name__ == "__main__":
    main()
