"""Reproduce the ClawHub finding on your own machine.

Downloads OpenClaw's public scan-results dataset, runs every skill in it
through the same OATS classifier the gateway uses, and reports how many
skills the registry's own scanners all call clean while still instructing
an agent to fetch code off the network and run it.

    pip install pheo-oats pandas pyarrow requests
    oats start --no-browser &
    python research/reproduce_clawhub.py

Defaults to the 3,339-skill eval_holdout split, which takes a few minutes.
Pass --split train for the full 66,192-skill corpus and a much longer wait.

Nothing here is privileged. The dataset is MIT licensed and public, the
classifier is the one in the wheel you installed, and the numbers printed
at the end are the ones quoted in the README.
"""
import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd
import requests

import extract

DATASET = "OpenClaw/clawhub-security-signals"
PARQUET_API = f"https://datasets-server.huggingface.co/parquet?dataset={DATASET}"

# Classes no freshly installed skill should run unattended. Mirrors the
# gateway's own never-graduates set, minus secret_change: that one fires
# correctly on any documented .env reference, which nearly every skill
# needing an API key has, making it a true classification and a weak
# risk signal. Including it roughly doubles the headline number for no
# gain in meaning.
UNEARNED = {
    "shell_remote_exec",
    "shell_credential_access",
    "shell_destructive",
    "iam_change",
    "deploy",
    "modify_github_actions",
    "manage_webhook",
    "delete_or_transfer_repo",
}
LABEL_TO_KEY = {
    "Remote code execution": "shell_remote_exec",
    "Credential access": "shell_credential_access",
    "Destructive command": "shell_destructive",
    "Shell command": "shell_exec",
    "Secrets": "secret_change",
    "IAM": "iam_change",
    "Deploy": "deploy",
    "Business logic": "business_logic",
    "File change": "apply_patch_to_branch",
    "Docs": "docs_write",
    "Tests": "test_write",
    "Dependencies": "dependency_change",
    "Boilerplate": "boilerplate_write",
    "Automation": "modify_github_actions",
    "Read": "read_files",
}


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
    urls = [f["url"] for f in files if f["split"] == split]
    if not urls:
        raise SystemExit(f"no parquet files for split {split!r}")
    frames = []
    for i, url in enumerate(urls):
        path = cache / f"{split}_{i:04d}.parquet"
        if not path.exists():
            print(f"  downloading {path.name} ...", flush=True)
            with requests.get(url, stream=True, timeout=600) as resp:
                resp.raise_for_status()
                with open(path, "wb") as fh:
                    for chunk in resp.iter_content(1 << 20):
                        fh.write(chunk)
        frames.append(pd.read_parquet(path))
    return pd.concat(frames, ignore_index=True).drop_duplicates("skill_slug")


def classify_one(args):
    """Every fenced block in one skill, through the real hook client."""
    oatsctl, gateway, room, row = args
    classes = set()
    for block in extract.fenced_blocks(row.skill_md_content or ""):
        try:
            proc = subprocess.run(
                [oatsctl, "hook", "pre-tool-use", "--gateway", gateway,
                 "--project", room, "--repo", "clawhub/reproduction",
                 "--agent-id", "reproduce", "--fail-open"],
                input=json.dumps(
                    {"tool_name": "Bash", "tool_input": {"command": block}}
                ),
                capture_output=True, text=True, timeout=30,
            )
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
            reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
        except Exception:
            continue
        label = reason.split(" to ")[0].split(" at ")[0].strip()
        key = LABEL_TO_KEY.get(label)
        if key:
            classes.add(key)
    return row.skill_slug, classes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="eval_holdout",
                    choices=["eval_holdout", "test", "validation", "train"])
    ap.add_argument("--gateway", default="http://127.0.0.1:8788")
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

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

    print("\nclassifying through the shipped OATS resolver ...")
    started = time.time()
    results = {}
    work = [(oatsctl, args.gateway, room, row) for row in df.itertuples()]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for i, (slug, classes) in enumerate(pool.map(classify_one, work), 1):
            results[slug] = classes
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
    print(f"skills in split                          {len(df):>8,}")
    print(f"called clean by all four scanners         {all_clean.sum():>8,}")
    print(f"...of those, instructing an unearned action {len(gap):>6,}")
    print(f"...from distinct publishers               {gap.publisher.nunique():>8,}")
    print("=" * 68)

    from collections import Counter
    counts = Counter(k for s in gap.oats_classes for k in s if k in UNEARNED)
    for key, n in counts.most_common():
        print(f"  {key:28} {n:>6,}")

    out = Path("clawhub_reproduction.csv")
    gap[["skill_slug", "clawscan_verdict", "skillspector_severity"]].to_csv(
        out, index=False
    )
    print(f"\nthe skills themselves: {out}")
    print("Every one is marked clean by the registry's own pipeline.")


if __name__ == "__main__":
    sys.exit(main())
