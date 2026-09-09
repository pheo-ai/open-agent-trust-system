"""Reproduce the ClawHub finding on your own machine.

Downloads OpenClaw's public scan-results dataset, runs every skill in it
through the same OATS classifier the gateway uses, and reports how many
skills the registry's own scanners all call clean while still instructing
an agent to fetch code off the network and run it.

    pip install pheo-oats pandas pyarrow requests
    oats start --no-browser &
    python research/reproduce_clawhub.py

That downloads about 1.6 GB and takes a few hours. It defaults to the whole
corpus, all four splits, 66,192 skills, because that is the population the
paper reports. Pass --split eval_holdout for a 3,339-skill smoke test; the
numbers will not match the paper and the script says so when you do.

Nothing here is privileged. The dataset is MIT licensed and public, the
classifier is the one in the wheel you installed, the class taxonomy is
spec/action-classes.json in this repository, and the numbers printed at the
end are the ones quoted in the paper.
"""
import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd
import requests

import extract

DATASET = "OpenClaw/clawhub-security-signals"
PARQUET_API = f"https://datasets-server.huggingface.co/parquet?dataset={DATASET}"
SPEC = Path(__file__).resolve().parent.parent / "spec" / "action-classes.json"

# The taxonomy is single-sourced from the published spec rather than
# restated here, so this script cannot drift from the gateway's own class
# set. An earlier version hardcoded 15 of the 33 labels, which silently
# dropped every occurrence of the two never-graduating classes whose
# labels were missing.
_CLASSES = json.loads(SPEC.read_text())
LABEL_TO_KEY = {c["label"]: c["key"] for c in _CLASSES}
NEVER_GRADUATES = {c["key"] for c in _CLASSES if not c["graduates"]}

# Of the never-graduating classes we exclude secret_change. It fires
# correctly on any documented .env reference, which nearly every skill
# needing an API key has, making it a true classification and a weak risk
# signal. Including it roughly doubles the headline number for no gain in
# meaning. Classes reachable only from GitHub or computer-use tool calls,
# never from a Bash command string, are left in and simply score zero;
# a zero is informative.
UNEARNED = NEVER_GRADUATES - {"secret_change"}


def find_oatsctl():
    """The binary shipped in the wheel, wherever pip put it."""
    try:
        import pheo_oats

        candidate = Path(pheo_oats.__file__).parent / "_bin" / "oatsctl"
        if candidate.exists():
            return str(candidate)
    except ImportError:
        pass
    raise SystemExit("pheo-oats is not installed. Run: pip install pheo-oats")


def make_room(gateway):
    """A scratch room to classify into. Observe mode; nothing is enforced."""
    r = requests.post(
        gateway + "/api/projects",
        json={"kind": "repo", "name": "clawhub-reproduction",
              "repo": "clawhub/reproduction"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["id"]


def download(split, cache=Path("clawhub-data")):
    cache.mkdir(exist_ok=True)
    files = requests.get(PARQUET_API, timeout=60).json()["parquet_files"]
    wanted = [f for f in files if split == "all" or f["split"] == split]
    if not wanted:
        raise SystemExit(f"no parquet files for split {split!r}")
    frames = []
    for f in wanted:
        name = f["url"].rstrip(".parquet").split("/")[-1]
        path = cache / f"{f['split']}_{name}.parquet"
        if not path.exists() or path.stat().st_size != f["size"]:
            print(f"  downloading {path.name} ({f['size'] / 1e6:.0f} MB) ...",
                  flush=True)
            with requests.get(f["url"], stream=True, timeout=1800) as resp:
                resp.raise_for_status()
                with open(path, "wb") as fh:
                    for chunk in resp.iter_content(1 << 22):
                        fh.write(chunk)
        frames.append(pd.read_parquet(path))
    df = pd.concat(frames, ignore_index=True)
    # skill_slug is already unique in the published corpus; this is a guard,
    # not a deduplication step, and it removes nothing on the current release.
    return df.drop_duplicates("skill_slug")


def classify_one(args):
    """Every fenced block in one skill, through the real hook client.

    Returns (slug, classes, n_errors). Errors are counted rather than
    swallowed: a block that fails to classify is not a block that
    classified as harmless, and the two must not be pooled.
    """
    oatsctl, gateway, room, row = args
    classes, errors = set(), 0
    for block in extract.fenced_blocks(row.skill_md_content or ""):
        try:
            proc = subprocess.run(
                [oatsctl, "hook", "pre-tool-use", "--gateway", gateway,
                 "--project", room, "--repo", "clawhub/reproduction",
                 "--agent-id", "reproduce"],
                input=json.dumps(
                    {"tool_name": "Bash", "tool_input": {"command": block}}
                ),
                capture_output=True, text=True, timeout=60,
            )
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
            reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
        except Exception:
            errors += 1
            continue
        label = reason.split(" to ")[0].split(" at ")[0].strip()
        key = LABEL_TO_KEY.get(label)
        if key:
            classes.add(key)
        else:
            errors += 1
    return row.skill_slug, classes, errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="all",
                    choices=["all", "eval_holdout", "test", "validation", "train"])
    ap.add_argument("--gateway", default="http://127.0.0.1:8788")
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

    if args.split != "all":
        print("=" * 68)
        print(f"  WARNING: --split {args.split} is a subset of the corpus.")
        print("  The paper reports over all four splits (66,192 skills).")
        print("  The numbers below will NOT match the paper. Use --split all.")
        print("=" * 68 + "\n")

    oatsctl = find_oatsctl()
    try:
        requests.get(args.gateway + "/api/projects", timeout=5).raise_for_status()
    except Exception:
        raise SystemExit(
            f"No gateway at {args.gateway}. Start one first:\n"
            f"    oats start --no-browser &"
        )
    room = make_room(args.gateway)
    print(f"gateway {args.gateway}  room {room}")

    print(f"\ndownloading split {args.split!r} ...")
    df = download(args.split)
    print(f"  {len(df):,} skills")

    # Extraction accounting, reported rather than left implicit.
    estats = {}
    for txt in df.skill_md_content.fillna(""):
        extract.fenced_blocks(txt, estats)
    print(f"  {estats.get('blocks', 0):,} shell blocks extracted; "
          f"{estats.get('tagged_nonshell', 0):,} fences skipped as non-shell; "
          f"{estats.get('truncated', 0):,} truncated at 2,000 chars")

    print("\nclassifying through the shipped OATS resolver ...")
    started = time.time()
    results, total_errors = {}, 0
    work = [(oatsctl, args.gateway, room, row) for row in df.itertuples()]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for i, (slug, classes, errs) in enumerate(pool.map(classify_one, work), 1):
            results[slug] = classes
            total_errors += errs
            if i % 250 == 0:
                rate = i / (time.time() - started)
                print(f"  {i:,}/{len(work):,}  ({rate:.0f}/s)", flush=True)

    df["oats_classes"] = df.skill_slug.map(results)
    df["unearned"] = df.oats_classes.apply(lambda s: bool(s & UNEARNED))
    all_clean = (
        df.clawscan_verdict.eq("clean")
        & df.virustotal_status.eq("clean")
        & df.static_status.eq("clean")
        & df.skillspector_status.eq("clean")
    )
    gap = df[all_clean & df.unearned].copy()
    gap["publisher"] = gap.skill_slug.str.split("/").str[0]

    print("\n" + "=" * 68)
    print(f"skills in corpus                            {len(df):>8,}")
    print(f"called clean by all four signals             {all_clean.sum():>8,}")
    print(f"...of those, instructing an unearned action  {len(gap):>8,}")
    print(f"...from distinct publishers                  {gap.publisher.nunique():>8,}")
    print(f"blocks that failed to classify               {total_errors:>8,}")
    print("=" * 68)

    counts = Counter(k for s in gap.oats_classes for k in s if k in UNEARNED)
    print("\nby class (a skill instructing two classes appears in both rows):")
    for key in sorted(UNEARNED):
        print(f"  {key:28} {counts.get(key, 0):>6,}")
    print(f"  {'sum of rows':28} {sum(counts.values()):>6,}  "
          f"vs {len(gap):,} distinct skills")

    print("\nper publisher, so a single vendor's repeated installer line is visible:")
    per_pub = gap.groupby("publisher").size().sort_values(ascending=False)
    print(f"  mean skills per publisher   {per_pub.mean():>8.2f}")
    print(f"  median                      {per_pub.median():>8.0f}")
    print(f"  largest single publisher    {per_pub.iloc[0]:>8,}  ({per_pub.index[0]})")

    out = Path("clawhub_reproduction.csv")
    gap[["skill_slug", "clawscan_verdict", "skillspector_severity"]].to_csv(
        out, index=False
    )
    print(f"\nthe skills themselves: {out}")
    print("Every one is marked clean by the registry's own pipeline.")


if __name__ == "__main__":
    sys.exit(main())
