"""Fail-closed change classification and merge decision used by CI and tests."""
import argparse
import json
from pathlib import PurePosixPath
import subprocess
import sys


# These Markdown documents are byte-pinned inputs or content assertions of OS
# gates, rather than prose-only references. Keep this list path-based: a deleted
# input must still require Foundry. test_review_boundaries audits gate references
# and reviewed source registries so a new executable document cannot evade it.
EXECUTABLE_DOCUMENTS = frozenset({
    'CONSTITUTION.md',
    'EVIDENCE_LEVELS.md',
    'NEXT_TASKS.md',
    'docs/BOOT_FRAME_OWNERSHIP_V0.md',
    'docs/DESKTOP_EDITOR_HOST_API_V0.md',
    'docs/DESKTOP_EDITOR_PROCESS_API_V0.md',
    'docs/DESKTOP_EDITOR_PROCESS_ASSERTIONS_V0.md',
    'docs/DESKTOP_EDITOR_NATIVE_READ_API_V0.md',
    'docs/DESKTOP_EDITOR_STORE_API_V0.md',
    'docs/DESKTOP_EDITOR_WIRE_V1.md',
    'docs/DESKTOP_SESSION_V1.md',
    'docs/FOUNDRY_CI_OPTIMIZATION_V0.md',
    'docs/HARDWARE_STRATEGY.md',
    'docs/HIL_APPLIANCE_EVIDENCE_V0.md',
    'docs/STORE_AUTHORITY_EPOCH_V1.md',
    'docs/plans/2026-02-20-s11-driver-factory-mvp.md',
    'docs/plans/2026-06-17-s10-5-1-broker-kernel-bridge.md',
    'docs/plans/2026-06-17-s10-5-2-qemu-ipc-bridge.md',
    'docs/plans/2026-06-17-s10-5-host-to-target-integration.md',
    'docs/plans/2026-06-21-s12-golden-machine-design.md',
    'docs/plans/2026-06-21-s13-persistent-storage-design.md',
    'docs/plans/2026-06-22-hil-appliance-controller.md',
    'docs/plans/desktop-editor-v0.md',
    'docs/plans/editor-store-transaction-v0.md',
    'docs/plans/editor-process-v0.md',
    'docs/plans/posix_runner_remaining_risks.md',
    'drivers/reference_vaults/virtio-blk/README.md',
    'drivers/reference_vaults/virtio-net/README.md',
})


def requires_foundry(paths):
    def documentation(path):
        # Only canonical repository-relative paths can receive a prose
        # exemption. Contract provenance may name external pinned documents;
        # those must fail closed rather than masquerading as local Markdown.
        if type(path) is not str or not path or "\\" in path or "\0" in path:
            return False
        p = PurePosixPath(path)
        if p.is_absolute() or ".." in p.parts or p.as_posix() != path:
            return False
        if (path in EXECUTABLE_DOCUMENTS
                or path.startswith('docs/contracts/') or 'fixtures' in p.parts):
            return False
        # Only genuine org packet locations get the structured-data exemption.
        # Unknown JSON/YAML elsewhere defaults to Foundry, including new inputs.
        return ((p.suffix == ".md" and not path.startswith(".github/"))
                or (path.startswith("docs/org/") and p.suffix in {".yaml", ".yml", ".json"}))
    return any(not documentation(path) for path in paths)


def changed_paths(base, head):
    if not base or not head:
        raise ValueError("change classification requires nonempty base and head refs")
    raw = subprocess.check_output([
        "git", "diff", "--no-renames", "--name-only", "-z", base, head, "--"])
    return [p.decode("utf-8", errors="strict") for p in raw.split(b"\0") if p]


def event_paths(event, head, pr_base="", push_base=""):
    """Return compared paths; None means explicitly requested full validation."""
    if event == "workflow_dispatch":
        return None
    if event == "pull_request":
        return changed_paths(pr_base, head)
    if event == "push":
        if push_base == "0" * 40:
            # The first main push has no predecessor. Compare the complete tree,
            # rather than confusing a missing base with a prose-only change.
            push_base = subprocess.check_output(
                ["git", "hash-object", "-t", "tree", "--stdin"], input=b"").decode().strip()
        return changed_paths(push_base, head)
    raise ValueError(f"unsupported CI event: {event!r}")


def classify_paths(paths):
    """Keep stdout machine-readable and explain costly routing in the job log."""
    if paths is None:
        print("Manual dispatch requests complete Foundry validation.", file=sys.stderr)
        return True
    required = [path for path in paths if requires_foundry([path])]
    print("Foundry-required changed paths: " + json.dumps(required), file=sys.stderr)
    return bool(required)


def merge_allowed(changes, os_code, foundry, governance):
    return (changes == "success" and governance == "success"
            and os_code in {"true", "false"}
            and (foundry == "success" if os_code == "true" else foundry in {"success", "skipped"}))


def foundry_allowed(changes, os_code, quality, host, agent, qemu, editor):
    """Only docs classification permits all lane jobs to skip."""
    if changes != "success" or os_code not in {"true", "false"}:
        return False
    expected = "success" if os_code == "true" else "skipped"
    return all(result == expected for result in (quality, host, agent, qemu, editor))


def main():
    parser = argparse.ArgumentParser(__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    classify = sub.add_parser("classify")
    classify.add_argument("base")
    classify.add_argument("head")
    event = sub.add_parser("event")
    event.add_argument("event")
    event.add_argument("--head", default="HEAD")
    event.add_argument("--pr-base", default="")
    event.add_argument("--push-base", default="")
    merge = sub.add_parser("merge")
    for name in ["changes", "os_code", "foundry", "governance"]:
        merge.add_argument(name)
    foundry = sub.add_parser("foundry")
    for name in ["changes", "os_code", "quality", "host", "agent", "qemu", "editor"]:
        foundry.add_argument(name)
    args = parser.parse_args()
    if args.command == "classify":
        print("true" if classify_paths(changed_paths(args.base, args.head)) else "false")
    elif args.command == "event":
        paths = event_paths(args.event, args.head, args.pr_base, args.push_base)
        print("true" if classify_paths(paths) else "false")
    elif args.command == "foundry":
        if not foundry_allowed(args.changes, args.os_code, args.quality, args.host, args.agent, args.qemu, args.editor):
            raise SystemExit("foundry: FAIL")
        print("foundry: PASS")
    elif not merge_allowed(args.changes, args.os_code, args.foundry, args.governance):
        raise SystemExit("merge-gate: FAIL")
    else:
        print("merge-gate: PASS")


if __name__ == "__main__":
    main()
