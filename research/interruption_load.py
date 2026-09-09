"""What the gate costs an operator, across a spectrum of operator policies.

A reviewer asked us for the gate's false-positive rate: how often does it
hold something the operator would have allowed. The number does not exist
as a single value, and saying why is more useful than inventing one.

A hold on a lane that has not graduated is not an error. It is what the
ledger is designed to do when there is no track record yet. Whether it is
*friction* depends entirely on which classes a given operator would have
waved through, and that is the operator's policy, not a property of the
gate. "Permitted" being operator-relative is this paper's whole thesis,
so a single false-positive rate would contradict it.

What can be reported without judgement is two things:

  load        how many times the gate interrupted, per skill installed,
              and which classes those interruptions were about.

  spectrum    for a stated policy, exactly how many of those
              interruptions that policy would have removed. The gate's
              decision is a function of the resolved class and the lane
              state, so given a set of auto-approved classes this is
              arithmetic rather than adjudication.

    python research/interruption_load.py live_agent_runtime.jsonl
"""
import json
import sys
from collections import Counter
from pathlib import Path

SPEC = Path(__file__).resolve().parent.parent / "spec" / "action-classes.json"
CLASSES = json.loads(SPEC.read_text())
NEVER_GRADUATES = {c["key"] for c in CLASSES if not c["graduates"]}
SEVERITY = {c["key"]: c["severity"] for c in CLASSES}

# Three operators, described by what they would let an agent do unattended
# in a repository they own. None of them is the "right" policy: they are
# three points on a spectrum, and an operator's own point is the input the
# system is built to take.
POLICIES = [
    ("strict",
     "Nothing runs unattended. Every action is reviewed.",
     set()),
    ("moderate",
     "Reads, docs, tests and ordinary shell go unattended in your own "
     "repository. Credentials, deploys, CI and remote code are reviewed.",
     {"read_files", "docs_write", "test_write", "shell_exec",
      "boilerplate_write", "propose_patch", "open_pr", "manage_issue_or_pr",
      "computer_observe", "connector_config"}),
    ("permissive",
     "Anything that can graduate does. Only the classes that never "
     "graduate are held.",
     {c["key"] for c in CLASSES if c["graduates"]}),
]


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "live_agent_runtime.jsonl")
    if not path.is_file():
        raise SystemExit("No record at %s. Run research/live_agent_study.py first." % path)
    rows = [json.loads(line) for line in path.open()]
    skills = {r["skill"] for r in rows}
    stopped = [r for r in rows if r["decision"] in ("hold", "block")]

    print("=" * 68)
    print("INTERRUPTION LOAD")
    print("=" * 68)
    print("  skills                       %6d" % len(skills))
    print("  decisions                    %6d   %5.1f per skill"
          % (len(rows), len(rows) / len(skills)))
    for decision in ("hold", "block"):
        n = sum(1 for r in rows if r["decision"] == decision)
        print("  %-28s %6d   %5.1f per skill"
              % (decision + "s", n, n / len(skills)))
    print()
    print("  what the interruptions were about:")
    for key, n in Counter(r["class"] for r in stopped).most_common():
        print("    %-26s %5d  %5.1f%%   severity %d%s"
              % (key, n, 100 * n / len(stopped), SEVERITY.get(key, -1),
                 "  (never graduates)" if key in NEVER_GRADUATES else ""))

    print()
    print("=" * 68)
    print("WHAT EACH POLICY WOULD HAVE REMOVED")
    print("=" * 68)
    print("  %-11s %8s %8s %9s   %s"
          % ("policy", "removed", "remain", "per skill", "of the interruptions"))
    for name, _, auto in POLICIES:
        # A class that never graduates is never auto-approved, whatever a
        # policy says: that rule is enforced in the authorisation path, not
        # configured.
        approved = {k for k in auto if k not in NEVER_GRADUATES}
        removed = sum(1 for r in stopped if r["class"] in approved)
        remain = len(stopped) - removed
        print("  %-11s %8d %8d %9.1f   %.0f%% removed"
              % (name, removed, remain, remain / len(skills),
                 100 * removed / len(stopped)))
    print()
    for name, description, _ in POLICIES:
        print("  %-11s %s" % (name, description))

    print()
    print("=" * 68)
    print("WHAT GRADUATION WOULD COST THE MODERATE OPERATOR")
    print("=" * 68)
    # The friction a moderate operator feels is concentrated in whichever
    # class dominates the holds. Graduating that one lane is what the
    # threshold derivation prices.
    dominant, count = Counter(
        r["class"] for r in stopped if r["class"] not in NEVER_GRADUATES
    ).most_common(1)[0]
    print("  dominant graduating class    %s  (%d of %d interruptions, %.0f%%)"
          % (dominant, count, len(stopped), 100 * count / len(stopped)))
    per_skill = count / len(skills)
    print("  at eps = 5%, that lane needs 59 consecutive clean approvals, with")
    print("  392 expected given the reset on rejection (see the paper).")
    print("  This workload generates %.1f of them per skill, so roughly %d skill"
          % (per_skill, round(392 / per_skill)))
    print("  installations before the lane stops asking. A developer doing")
    print("  ordinary work in the same repository would get there sooner: the")
    print("  cost is 392 approvals, not 392 skills.")

    # Two policies landing on the same number is not a bug in either.
    distinct = {sum(1 for r in stopped
                    if r["class"] in {k for k in auto if k not in NEVER_GRADUATES})
                for _, _, auto in POLICIES}
    if len(distinct) < len(POLICIES):
        print()
        print("  Note: moderate and permissive coincide here. The only")
        print("  graduating class this workload produced is shell_exec, which")
        print("  both auto-approve, so the spectrum has two points rather than")
        print("  three. A workload touching file writes, merges or releases")
        print("  would separate them.")


if __name__ == "__main__":
    sys.exit(main())
