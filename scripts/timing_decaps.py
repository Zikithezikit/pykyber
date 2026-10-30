#!/usr/bin/env python3
"""Statistical timing test of decapsulation (PLAN-2.0 WP-8, issue #16).

A dudect-style measurement tool, not a correctness test: it is not part of
`cargo test`, `pytest` or scripts/check.sh because it is slow and its result
depends on the machine. Run it by hand before a release (see SECURITY.md).

What it measures. For one fixed key pair it times decapsulation of three
classes of ciphertext through the private extension functions (no Python
wrapper, so the only Python in the timed window is the call itself):

  valid    ciphertexts from encapsulate();
  flip     a valid ciphertext with one bit flipped (a near miss, the case in
           which an early-exit comparison would leak the position);
  random   uniformly random bytes of the right length (rejected as well).

Implicit rejection means all three return a 32-byte secret and none raises, so
a difference in running time between "valid" and the others is exactly the
leak of the comparison/select code that this test looks for.

Method. The classes are interleaved in a random order (fixed seed) to spread
drift and cache effects over all classes. Each class draws from a pool of
distinct ciphertexts. For each pair (valid vs flip, valid vs random) Welch's
t statistic is computed on the raw timings and after cropping the slowest
values at several percentiles of the pooled data (dudect's way of dealing
with the heavy right tail of timing noise). A pair is flagged only if |t|
exceeds the threshold on the whole run and on both halves of the run (by time)
with the same sign.

Reproducibility. The key pair (from a fixed 64-byte seed), the bit positions,
the random ciphertexts, the pool indices and the measurement order are all
derived from --seed. The valid ciphertexts are not reproducible byte for byte:
encapsulate() draws its message from the OS generator and the extension offers
no seeded variant. They are identically distributed, so this does not matter
for the statistic, but two runs are not bit-identical.

Power. The tool prints the smallest mean difference it could have detected at
the threshold (from the observed variances). A run on a noisy machine has a
large detectable difference and then proves little. `--inject-ns N` is a
positive control: it adds N ns of busy-waiting to the non-valid classes
inside the timed window; run it to see what the test does detect on this
machine. Nothing here proves constant time; it fails to find a leak of some
size, with one compiler, one CPU and one run.

Build the extension in release mode first: `maturin develop --release`.
"""

import argparse
import gc
import math
import os
import platform
import random
import sys
import time

DEFAULT_COUNT = 100000      # measurements per class
DEFAULT_SEED = 20261030     # the date of the WP-8 work, as an integer
DEFAULT_THRESHOLD = 5.0     # |t|; one test p ~ 6e-7, ten tests per set < 1e-5
POOL_SIZE = 256             # distinct ciphertexts per class
WARMUP = 2000               # untimed calls before measuring
CROP_PERCENTILES = (100, 99, 95, 90, 80)   # 100 = no cropping
SEED_BYTES = 64             # d || z for ML-KEM, the same layout for legacy keygen
SETS = ("512", "768", "1024")
FAMILIES = ("mlkem", "kyber")


def load_functions(family, level):
    from pykyber import _pykyber as ext
    if family == "mlkem":
        keygen = getattr(ext, "_mlkem_%s_keygen" % level)
        encaps = getattr(ext, "_mlkem_%s_encaps" % level)
        decaps = getattr(ext, "_mlkem_%s_decaps" % level)
        # ML-KEM: keygen -> (ek, dk), encaps -> (c, K), decaps(c, dk)
        return keygen, encaps, decaps
    keygen = getattr(ext, "_keypair_%s" % level)
    encaps = getattr(ext, "_encapsulate_%s" % level)
    decaps = getattr(ext, "_decapsulate_%s" % level)
    # legacy: keygen -> (pk, sk), encaps -> (ct, ss), decaps(ct, sk)
    return keygen, encaps, decaps


def welch_t(a, b):
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return 0.0, 0.0
    ma, mb = sum(a) / na, sum(b) / nb
    va = sum((x - ma) ** 2 for x in a) / (na - 1)
    vb = sum((x - mb) ** 2 for x in b) / (nb - 1)
    se = math.sqrt(va / na + vb / nb)
    if se == 0:
        return 0.0, 0.0
    return (ma - mb) / se, se


def percentile(sorted_values, pct):
    idx = min(len(sorted_values) - 1, int(len(sorted_values) * pct / 100.0))
    return sorted_values[idx]


def analyse(label, valid, other, threshold):
    """valid, other: lists of (index_in_run, ns). Returns (flagged, lines)."""
    pooled = sorted(v for _, v in valid) + sorted(v for _, v in other)
    pooled.sort()
    lines = []
    flagged = False
    for pct in CROP_PERCENTILES:
        cut = percentile(pooled, pct) if pct < 100 else float("inf")
        a = [v for _, v in valid if v <= cut]
        b = [v for _, v in other if v <= cut]
        t_all, se = welch_t(a, b)
        # halves by time: the run index is shared by all classes
        mid = max(i for i, _ in valid + other) // 2
        t_first, _ = welch_t([v for i, v in valid if i <= mid and v <= cut], [v for i, v in other if i <= mid and v <= cut])
        t_second, _ = welch_t([v for i, v in valid if i > mid and v <= cut], [v for i, v in other if i > mid and v <= cut])
        mean_diff = (sum(a) / len(a) - sum(b) / len(b)) if a and b else 0.0
        mde = threshold * se
        hit = (abs(t_all) > threshold and abs(t_first) > threshold and abs(t_second) > threshold
               and (t_all > 0) == (t_first > 0) == (t_second > 0))
        flagged = flagged or hit
        lines.append("  %-14s crop<=p%-3d t=%+8.2f (halves %+7.2f %+7.2f)  mean(valid)-mean(other)=%+9.1f ns  "
                     "detectable at |t|=%.1f: %7.1f ns  n=%d/%d  %s"
                     % (label, pct, t_all, t_first, t_second, mean_diff, threshold, mde, len(a), len(b),
                        "LEAK?" if hit else "ok"))
    return flagged, lines


def run_one(family, level, count, seed, threshold, inject_ns):
    keygen, encaps, decaps = load_functions(family, level)
    rng = random.Random("%s-%s-%d" % (family, level, seed))
    key_seed = bytes(rng.getrandbits(8) for _ in range(SEED_BYTES))
    pub, sec = keygen(key_seed)
    pub, sec = bytes(pub), bytes(sec)

    valid_pool = [bytes(encaps(pub)[0]) for _ in range(POOL_SIZE)]
    ct_len = len(valid_pool[0])
    flip_pool = []
    for i in range(POOL_SIZE):
        ct = bytearray(valid_pool[rng.randrange(POOL_SIZE)])
        pos = rng.randrange(ct_len * 8)
        ct[pos // 8] ^= 1 << (pos % 8)
        flip_pool.append(bytes(ct))
    random_pool = [bytes(rng.getrandbits(8) for _ in range(ct_len)) for _ in range(POOL_SIZE)]
    pools = {"valid": valid_pool, "flip": flip_pool, "random": random_pool}

    # sanity: decapsulation of a valid ciphertext must agree with encaps
    c0, k0 = encaps(pub)
    assert bytes(decaps(bytes(c0), sec)) == bytes(k0), "decapsulation does not round-trip"
    assert bytes(decaps(flip_pool[0], sec)) != bytes(k0)

    schedule = ["valid", "flip", "random"] * count
    rng.shuffle(schedule)
    picks = [rng.randrange(POOL_SIZE) for _ in schedule]

    clock = time.perf_counter_ns
    for k in range(WARMUP):
        decaps(valid_pool[k % POOL_SIZE], sec)

    results = {"valid": [], "flip": [], "random": []}
    gc.collect()
    gc.disable()
    try:
        for i, (cls, pick) in enumerate(zip(schedule, picks)):
            ct = pools[cls][pick]
            t0 = clock()
            decaps(ct, sec)
            if inject_ns and cls != "valid":
                end = t0 + inject_ns
                while clock() < end:
                    pass
            t1 = clock()
            results[cls].append((i, t1 - t0))
    finally:
        gc.enable()

    print("\n== %s %s: %d measurements per class, ciphertext %d bytes, threshold |t| > %.1f%s"
          % (family, level, count, ct_len, threshold,
             ", INJECTED %d ns into the non-valid classes" % inject_ns if inject_ns else ""))
    med = sorted(v for _, v in results["valid"])
    print("  valid-class timing: median %d ns, p5 %d ns, p95 %d ns" % (percentile(med, 50), percentile(med, 5), percentile(med, 95)))
    flagged = False
    for other in ("flip", "random"):
        hit, lines = analyse("valid/" + other, results["valid"], results[other], threshold)
        flagged = flagged or hit
        print("\n".join(lines))
    return flagged


def describe_machine():
    model = "?"
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    governor = "?"
    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
            governor = f.read().strip()
    except OSError:
        pass
    import pykyber
    print("python   : %s %s" % (platform.python_implementation(), platform.python_version()))
    print("machine  : %s, %s, governor %s" % (platform.machine(), model, governor))
    print("pykyber  : %s from %s" % (getattr(pykyber, "__version__", "?"), os.path.dirname(pykyber.__file__)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--family", default=",".join(FAMILIES), help="comma list of: " + ",".join(FAMILIES))
    ap.add_argument("--sets", default="768", help="comma list of: " + ",".join(SETS))
    ap.add_argument("-n", "--count", type=int, default=DEFAULT_COUNT, help="measurements per class (default %(default)d)")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--cpu", type=int, default=None, help="pin the process to this CPU (Linux)")
    ap.add_argument("--inject-ns", type=int, default=0, help="positive control: add this many ns to non-valid classes")
    args = ap.parse_args()

    if args.cpu is not None and hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {args.cpu})
    print("== environment")
    describe_machine()
    print("count    : %d per class, seed %d, threshold |t| > %.1f, pool %d, warmup %d"
          % (args.count, args.seed, args.threshold, POOL_SIZE, WARMUP))

    any_flag = False
    for family in args.family.split(","):
        for level in args.sets.split(","):
            any_flag = run_one(family.strip(), level.strip(), args.count, args.seed, args.threshold, args.inject_ns) or any_flag

    print("\n== result")
    if args.inject_ns:
        if any_flag:
            print("positive control: the injected %d ns difference WAS flagged" % args.inject_ns)
            return 0
        print("positive control: the injected %d ns difference was NOT flagged; the test is too weak at this count/noise" % args.inject_ns)
        return 1
    if any_flag:
        print("LEAK? flagged above: repeat on a quiet machine (--cpu N) before drawing conclusions")
        return 1
    print("no timing difference found at the stated power (not a proof of constant time)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
