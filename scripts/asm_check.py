#!/usr/bin/env python3
"""Compiler-level check of the release build (PLAN-2.0 WP-8, issue #16).

KyberSlash (division by q) and CVE-2024-37880 (a mask turned into a branch)
came from the compiler, not from the source. This script builds the library
for several targets in release mode, disassembles it and looks at what the
compiler actually emitted for the decapsulation paths of ML-KEM and of the
legacy Kyber code.

How the functions are found. Nothing under src/ is changed and no probe crate
is needed: `cargo rustc --release --lib --crate-type rlib` builds the same
objects as the shipped build (same profile, same codegen units) and needs no
linker, so it also works for targets we cannot link on this machine. rustc puts
every function in its own section, so llvm-objdump gives one body per symbol.
The roots are the decapsulation entry points (ML-KEM `mlkem::kem::decaps`,
legacy `kyber::kem::crypto_kem_dec*`). The script follows the call relocations
and checks every function reachable from a root, because inlining moves
`poly_from_msg`, `compress` and friends between symbols from one compiler
release to the next. The named leaf functions are listed when they exist as
symbols of their own, or reported as inlined.

Checks, per function in the closure:
  division   a div/idiv/udiv/sdiv instruction, or a call to a division
             helper (__udivdi3, __aeabi_idiv, ...), or the panic for a
             division by a non-constant (KyberSlash class).
  variable-time memory compare   a call to memcmp/bcmp/strcmp.
  indirect branch   jump tables and computed jumps (a secret index).
  conditional branches   a tool cannot tell a secret branch from a public
             one, so every conditional branch is classified by shape:
               loop    backward branch (a loop back edge),
               panic   one side is a block that ends in a panic call
                       (bounds and length checks),
               other   everything else.
             "other" branches must be listed per function in
             scripts/asm_check_allowlist.json with a reason and a ceiling.
             A function that is not listed, or that has more than its
             ceiling, is a finding. Each allowlist entry was reviewed by
             reading the listing printed by --show-other.

What this does not prove: loop and panic branches are assumed to depend on
public lengths and counters (the loop bounds are visible in the source); a
passing run is evidence for one compiler, one flag set and the targets named
in the report, not a constant-time guarantee.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import OrderedDict, defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOWLIST = os.path.join(REPO, "scripts", "asm_check_allowlist.json")

# name, rust triple, family, depth. "full" targets also print the branch
# detail; "spot" targets (32-bit, shipped in the wheels) get the same checks.
TARGETS = OrderedDict(
    [
        ("x86_64", ("x86_64-unknown-linux-gnu", "x86", "full")),
        ("aarch64", ("aarch64-unknown-linux-gnu", "arm64", "full")),
        ("i686", ("i686-unknown-linux-gnu", "x86", "spot")),
        ("armv7", ("armv7-unknown-linux-gnueabihf", "arm", "spot")),
    ]
)

# Decapsulation entry points. The ML-KEM symbol is generic over K, so the
# three parameter sets are three symbols with the same demangled name.
ROOTS = [
    ("ML-KEM", r"^pykyber::mlkem::kem::decaps$"),
    ("legacy Kyber", r"^pykyber::kyber::kem::crypto_kem_dec(_512|_1024)?$"),
]

# Leaf functions named in issue #16. Matched against the name without hash.
LEAVES = [
    ("poly_tomsg (legacy)", r"^pykyber::kyber::poly::poly_tomsg$"),
    ("poly_frommsg (legacy)", r"^pykyber::kyber::poly::poly_frommsg$"),
    ("poly_compress (legacy)", r"^pykyber::kyber::poly::poly_compress(_1024)?$"),
    ("polyvec_compress (legacy)", r"^pykyber::kyber::polyvec::polyvec_compress(_1024|_512)?$"),
    ("poly_decompress (legacy)", r"^pykyber::kyber::poly::poly_decompress(_1024)?$"),
    ("verify (legacy)", r"^pykyber::kyber::verify::verify$"),
    ("cmov (legacy)", r"^pykyber::kyber::verify::cmov$"),
    ("poly_compress (ML-KEM)", r"^pykyber::mlkem::compress::poly_compress$"),
    ("poly_decompress (ML-KEM)", r"^pykyber::mlkem::compress::poly_decompress$"),
    ("poly_from_msg (ML-KEM)", r"^pykyber::mlkem::compress::poly_from_msg$"),
    ("reject_on_mismatch (ML-KEM)", r"^pykyber::mlkem::ct::reject_on_mismatch$"),
]

DIV_INSN = re.compile(r"^(i?div[bwlq]?|udiv|sdiv)$")
DIV_CALL = re.compile(
    r"(^__(u|s)?(div|mod)(si|di|ti)3$)|(^__u?divmod(si|di|ti)4$)|(^__aeabi_(u|i)?l?div)|"
    r"(^__aeabi_.*divmod)|(div_by_zero)|(rem_by_zero)|(^__(u|s)?divmoddi4$)"
)
MEMCMP_CALL = re.compile(r"^(memcmp|bcmp|strcmp|strncmp)$|core::slice::cmp|compiler_builtins::mem::(memcmp|bcmp)")
PANIC_CALL = re.compile(
    r"core::panicking::|core::slice::index::|core::result::unwrap_failed|"
    r"core::option::(expect|unwrap)_failed|core::slice::<impl \[T\]>::copy_from_slice::len_mismatch_fail|"
    r"slice_(start|end)_index|slice_index_order_fail|panic_bounds_check|len_mismatch_fail|"
    r"alloc::raw_vec::|alloc::alloc::handle_alloc_error|capacity_overflow|core::unreachable|"
    r"rust_panic|std::panicking::|core::str::|core::cell::panic|core::array::"
)

COND_X86 = re.compile(r"^j(?!mp$)[a-z]+$")
ARM_CC = r"(eq|ne|hs|cs|lo|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)"
COND_ARM_BRANCH = re.compile(r"^(b|bl|bx|blx)" + ARM_CC + r"(\.[nw])?$")
COND_ARM_PC = re.compile(r"^(pop|ldr|ldm[a-z]*|mov)" + ARM_CC + r"(\.[nw])?$")
COND_A64 = re.compile(r"^(b\.[a-z]{2}|cbz|cbnz|tbz|tbnz)$")

HASH = re.compile(r"::h[0-9a-f]{16}\b")
LLVM_SUFFIX = re.compile(r"\s*\(\.llvm\.\d+\)|\.llvm\.\d+")
FUNC_RE = re.compile(r"^[0-9a-f]+ <(.+)>:$")
SECTION_RE = re.compile(r"^Disassembly of section (\S+):$")
INSN_RE = re.compile(r"^\s+([0-9a-f]+):\s+(.*)$")
RELOC_RE = re.compile(r"^\s+[0-9a-f]+:\s+(R_\S+)\s+(.*)$")
TARGET_RE = re.compile(r"0x([0-9a-f]+)")


def norm(name):
    return LLVM_SUFFIX.sub("", name).strip()


def key(name):
    """Name without the hash, for the allowlist and the root patterns."""
    return HASH.sub("", norm(name))


def strip_addend(sym):
    return re.sub(r"[+-]0x[0-9a-f]+$", "", sym.strip())


class Insn(object):
    __slots__ = ("addr", "mnem", "ops", "reloc", "reloc_type")

    def __init__(self, addr, mnem, ops):
        self.addr = addr
        self.mnem = mnem
        self.ops = ops
        self.reloc = None
        self.reloc_type = None


class Func(object):
    def __init__(self, name, section):
        self.name = name
        self.section = section
        self.insns = []

    @property
    def key(self):
        return key(self.name)


def run(cmd, **kw):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, **kw)


def find_objdump(explicit, toolchain):
    if explicit:
        return explicit
    tc = ["+" + toolchain] if toolchain else []
    sysroot = run(["rustc"] + tc + ["--print", "sysroot"]).stdout.strip()
    host = [l.split(": ")[1] for l in run(["rustc"] + tc + ["-vV"]).stdout.splitlines() if l.startswith("host:")][0]
    cand = os.path.join(sysroot, "lib", "rustlib", host, "bin", "llvm-objdump")
    if os.path.exists(cand):
        return cand
    found = shutil.which("llvm-objdump")
    if found:
        return found
    sys.exit("llvm-objdump not found: run `rustup component add llvm-tools` or pass --objdump")


def build(triple, target_dir, toolchain):
    cmd = ["cargo"] + (["+" + toolchain] if toolchain else []) + [
        "rustc", "--locked", "--release", "--lib", "--crate-type", "rlib",
        "--target", triple, "--target-dir", target_dir,
    ]
    p = run(cmd, cwd=REPO)
    if p.returncode != 0:
        sys.exit("build failed for %s:\n%s" % (triple, p.stderr[-3000:]))
    rlib = os.path.join(target_dir, triple, "release", "libpykyber.rlib")
    if not os.path.exists(rlib):
        sys.exit("no rlib at " + rlib)
    return rlib


def disassemble(objdump, rlib):
    p = run([objdump, "-C", "-d", "-r", "--no-show-raw-insn", rlib])
    if p.returncode != 0:
        sys.exit("objdump failed: " + p.stderr[-2000:])
    return p.stdout


def parse(text):
    """Returns (funcs by normalized name, section name -> normalized name)."""
    funcs = OrderedDict()
    sections = {}
    cur = None
    section = None
    last = None
    for line in text.splitlines():
        m = SECTION_RE.match(line)
        if m:
            section = m.group(1)
            cur = None
            continue
        m = FUNC_RE.match(line)
        if m:
            name = norm(m.group(1))
            cur = Func(name, section)
            funcs[name] = cur
            sections[section] = name
            last = None
            continue
        if cur is None:
            continue
        m = RELOC_RE.match(line)
        if m:
            if last is not None:
                last.reloc = strip_addend(m.group(2))
                last.reloc_type = m.group(1)
            continue
        m = INSN_RE.match(line)
        if m:
            body = m.group(2).split("//")[0].split(";")[0].strip()
            if not body:
                continue
            parts = body.split(None, 1)
            mnem = parts[0]
            # x86 prefixes
            while mnem in ("rep", "repz", "repnz", "lock", "notrack", "bnd") and len(parts) > 1:
                parts = parts[1].split(None, 1)
                mnem = parts[0]
            ops = parts[1] if len(parts) > 1 else ""
            last = Insn(int(m.group(1), 16), mnem, ops)
            cur.insns.append(last)
    return funcs, sections


def is_indirect(insn, family):
    m = insn.mnem
    if family == "x86":
        return m.startswith("jmp") and "*" in insn.ops
    if family == "arm64":
        return m in ("br", "braa", "brab", "braaz", "brabz")
    return m in ("tbb", "tbh", "bx", "bx.n") and not re.search(r"\blr\b", insn.ops) or (
        m in ("ldr", "mov", "add") and re.match(r"^pc\b", insn.ops) is not None)


def callee_name(insn, sections):
    sym = insn.reloc
    if sym is None:
        return None
    if sym.startswith(".text."):
        return sections.get(sym)
    return norm(sym)


def is_transfer(insn, family):
    m = insn.mnem
    if family == "x86":
        return m == "ret" or m.startswith("jmp") or m.startswith("call") or COND_X86.match(m) is not None
    if family == "arm64":
        return m in ("ret", "b", "bl", "br", "blr") or COND_A64.match(m) is not None
    return m in ("b", "bl", "bx", "blx", "b.w", "b.n") or COND_ARM_BRANCH.match(m) is not None


def is_call(insn, family):
    m = insn.mnem
    if family == "x86":
        return m.startswith("call")
    if family == "arm64":
        return m in ("bl", "blr")
    return m in ("bl", "blx")


def cond_kind(insn, family):
    m = insn.mnem
    if family == "x86":
        return COND_X86.match(m) is not None
    if family == "arm64":
        return COND_A64.match(m) is not None
    if COND_ARM_BRANCH.match(m) or m in ("cbz", "cbnz"):
        return True
    return COND_ARM_PC.match(m) is not None and re.search(r"\bpc\b", insn.ops) is not None


def local_target(insn):
    """Target address of an intra-function jump, or None."""
    if insn.reloc is not None:
        return None
    m = TARGET_RE.search(insn.ops)
    return int(m.group(1), 16) if m else None


def block_panics(func, start_addr, index, sections, family, depth=0):
    """True if the block at start_addr ends in a call to a panic function."""
    i = index.get(start_addr)
    if i is None:
        return False
    for insn in func.insns[i:]:
        if is_transfer(insn, family):
            callee = callee_name(insn, sections)
            if is_call(insn, family) or insn.reloc is not None:
                return callee is not None and PANIC_CALL.search(callee) is not None
            t = local_target(insn)
            if insn.mnem.startswith("jmp") or insn.mnem in ("b", "b.w", "b.n"):
                if t is not None and depth < 3:
                    return block_panics(func, t, index, sections, family, depth + 1)
            return False
    return False


def analyse_func(func, sections, family):
    """Returns dict with divisions, memcmps, indirect, callees, branches."""
    index = {insn.addr: n for n, insn in enumerate(func.insns)}
    res = {"div": [], "memcmp": [], "indirect": [], "callees": set(), "ext": set(),
           "loop": [], "panic": [], "other": []}
    for n, insn in enumerate(func.insns):
        if DIV_INSN.match(insn.mnem):
            res["div"].append((insn.addr, insn.mnem + " " + insn.ops))
        callee = callee_name(insn, sections)
        # Any call or jump that carries a relocation names its target: a
        # direct call (PLT32, CALL26), or a call through the GOT on x86
        # (`callq *(%rip)` with GOTPCREL), which is how the shipped code is linked.
        if callee is not None and (is_call(insn, family) or is_transfer(insn, family)):
            res["callees"].add(callee)
            if DIV_CALL.search(callee):
                res["div"].append((insn.addr, "call " + callee))
            if MEMCMP_CALL.search(callee):
                res["memcmp"].append((insn.addr, "call " + callee))
        # A computed jump has no relocation; `jmp *GOT(%rip)` is a tail call.
        if insn.reloc is None and is_indirect(insn, family):
            res["indirect"].append((insn.addr, insn.mnem + " " + insn.ops))
        if not cond_kind(insn, family):
            continue
        # An externally targeted conditional (tail call) has a relocation.
        t = local_target(insn)
        nxt = func.insns[n + 1].addr if n + 1 < len(func.insns) else None
        item = (insn.addr, insn.mnem + " " + insn.ops, n, flag_setter(func, n, family))
        if t is not None and t <= insn.addr:
            res["loop"].append(item)
        elif block_panics(func, t, index, sections, family) if t is not None else False:
            res["panic"].append(item)
        elif nxt is not None and block_panics(func, nxt, index, sections, family):
            res["panic"].append(item)
        else:
            res["other"].append(item)
    return res


X86_FLAGS = re.compile(r"^(cmp|test|sub|add|and|or|xor|neg|inc|dec|shl|shr|sar|sal|adc|sbb|bt[src]?|bsf|bsr|tzcnt|lzcnt|popcnt)[bwlq]?$")
A64_FLAGS = re.compile(r"^(cmp|cmn|tst|ccmp|ccmn|fcmp|[a-z]+s)$")
ARM_FLAGS = re.compile(r"^(cmp|cmn|tst|teq|[a-z]{2,5}s)(\.[nw])?$")


def flag_setter(func, n, family):
    """Nearest earlier instruction that writes the condition flags (display only)."""
    pat = {"x86": X86_FLAGS, "arm64": A64_FLAGS, "arm": ARM_FLAGS}[family]
    insn = func.insns[n]
    if insn.mnem in ("cbz", "cbnz", "cbz.n", "cbnz.n", "tbz", "tbnz"):
        return "(tests register itself)"
    for k in range(n - 1, max(-1, n - 40), -1):
        prev = func.insns[k]
        if pat.match(prev.mnem):
            return "%s %s" % (prev.mnem, prev.ops)
    return "?"


def closure(funcs, roots, results):
    seen = OrderedDict()
    work = list(roots)
    while work:
        name = work.pop()
        if name in seen or name not in funcs:
            continue
        seen[name] = funcs[name]
        for c in results[name]["callees"]:
            if c in funcs and c not in seen:
                work.append(c)
    return seen


def load_allowlist():
    with open(ALLOWLIST) as f:
        data = json.load(f)
    return data


def show_context(func, item):
    return "      +0x%-5x %-34s <- %s" % (item[0], item[1].split(" <")[0][:34], item[3])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--targets", default=",".join(TARGETS), help="comma list of: " + ",".join(TARGETS))
    ap.add_argument("--toolchain", default=None, help="rustup toolchain name, e.g. stable or 1.95.0")
    ap.add_argument("--objdump", default=None, help="path to llvm-objdump (default: from the rust sysroot)")
    ap.add_argument("--target-dir", default=None, help="build directory (default: a temp dir, removed on exit)")
    ap.add_argument("--show-other", action="store_true", help="print the code around every 'other' branch")
    ap.add_argument("--dump", default=None, help="write the disassembly of each target into this directory")
    args = ap.parse_args()

    objdump = find_objdump(args.objdump, args.toolchain)
    tc = ["+" + args.toolchain] if args.toolchain else []
    print("== environment")
    print("rustc    : " + run(["rustc"] + tc + ["-V"]).stdout.strip())
    print("cargo    : " + run(["cargo"] + tc + ["-V"]).stdout.strip())
    print("objdump  : " + objdump + " (" + run([objdump, "--version"]).stdout.splitlines()[1].strip() + ")")
    print("RUSTFLAGS: " + repr(os.environ.get("RUSTFLAGS", "")) + "  profile: release (opt-level 3, codegen-units 16, no LTO)")
    allow = load_allowlist()
    allow_funcs = dict((e["function"], e) for e in allow["other_branches"])
    ok_calls = allow.get("memcmp_calls", {})

    tmp = None
    target_dir = args.target_dir
    if target_dir is None:
        tmp = tempfile.mkdtemp(prefix="pykyber-asm-")
        target_dir = tmp
    findings = []
    try:
        for tname in [t.strip() for t in args.targets.split(",") if t.strip()]:
            if tname not in TARGETS:
                sys.exit("unknown target " + tname)
            triple, family, depth = TARGETS[tname]
            print("\n==== %s (%s, %s check)" % (tname, triple, depth))
            rlib = build(triple, target_dir, args.toolchain)
            text = disassemble(objdump, rlib)
            if args.dump:
                if not os.path.isdir(args.dump):
                    os.makedirs(args.dump)
                with open(os.path.join(args.dump, tname + ".txt"), "w") as f:
                    f.write(text)
            funcs, sections = parse(text)
            results = dict((n, analyse_func(f, sections, family)) for n, f in funcs.items())
            shown = set()
            print("%d function symbols, %d instructions" % (len(funcs), sum(len(f.insns) for f in funcs.values())))

            print("\nleaf functions of interest (standalone symbols):")
            for label, pat in LEAVES:
                hits = [f for f in funcs.values() if re.match(pat, f.key)]
                print("  %-30s %s" % (label, "%d symbol(s)" % len(hits) if hits else "inlined (checked inside its callers)"))

            for rlabel, rpat in ROOTS:
                roots = [n for n, f in funcs.items() if re.match(rpat, f.key)]
                if not roots:
                    findings.append("%s: no root symbol for %s (pattern %s)" % (tname, rlabel, rpat))
                    print("\n[%s] NO ROOT FOUND" % rlabel)
                    continue
                cl = closure(funcs, roots, results)
                print("\n[%s] %d root symbol(s), %d functions in the call closure, %d instructions"
                      % (rlabel, len(roots), len(cl), sum(len(f.insns) for f in cl.values())))
                agg = defaultdict(lambda: {"loop": 0, "panic": 0, "other": 0, "n": 0, "max_other": 0})
                for name, f in cl.items():
                    r = results[name]
                    a = agg[f.key]
                    a["n"] += 1
                    a["loop"] += len(r["loop"])
                    a["panic"] += len(r["panic"])
                    a["other"] += len(r["other"])
                    a["max_other"] = max(a["max_other"], len(r["other"]))
                    where = "%s [%s]" % (f.key, rlabel)
                    for addr, txt in r["div"]:
                        findings.append("%s: DIVISION in %s at +0x%x: %s" % (tname, where, addr, txt))
                    for addr, txt in r["indirect"]:
                        findings.append("%s: INDIRECT BRANCH in %s at +0x%x: %s" % (tname, where, addr, txt))
                    cmp_ok = ok_calls.get(f.key, {}).get("max", {}).get(tname, 0)
                    if len(r["memcmp"]) > cmp_ok:
                        for addr, txt in r["memcmp"]:
                            findings.append("%s: VARIABLE-TIME COMPARE in %s at +0x%x: %s (allowed: %d)"
                                            % (tname, where, addr, txt, cmp_ok))
                    ent = allow_funcs.get(f.key)
                    n_other = len(r["other"])
                    ceiling = ent["max"].get(tname, 0) if ent is not None else 0
                    if n_other > ceiling:
                        findings.append("%s: %s has %d unreviewed 'other' conditional branch(es), allowlist ceiling %d"
                                        " (review with --show-other, then update scripts/asm_check_allowlist.json)"
                                        % (tname, where, n_other, ceiling))
                    if args.show_other and n_other and name not in shown:
                        shown.add(name)
                        print("  -- %s: %d other branch(es)" % (f.key, n_other))
                        for it in r["other"]:
                            print(show_context(f, it))
                print("  %-58s %3s %5s %5s %5s" % ("function (hash removed)", "n", "loop", "panic", "other"))
                print("  (loop, panic: summed over the n symbols of that name; other: the largest of them)")
                for k in sorted(agg):
                    a = agg[k]
                    flag = ""
                    if a["max_other"]:
                        e = allow_funcs.get(k)
                        flag = "  allowlist: " + (e["group"] if e else "NOT IN ALLOWLIST")
                    print("  %-58s %3d %5d %5d %5d%s" % (k[:58], a["n"], a["loop"], a["panic"], a["max_other"], flag))
                divs = sum(len(results[n]["div"]) for n in cl)
                inds = sum(len(results[n]["indirect"]) for n in cl)
                cmps = sum(len(results[n]["memcmp"]) for n in cl)
                print("  division instructions/calls: %d, indirect branches: %d, memcmp-like calls: %d" % (divs, inds, cmps))
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    print("\n== result")
    if findings:
        seen = set()
        for f in findings:
            if f not in seen:
                print("FINDING: " + f)
                seen.add(f)
        print("%d finding(s)" % len(seen))
        return 1
    print("no findings (this is evidence for the toolchain and targets above, not a guarantee)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
