"""Host-only regressions for CI policy, efivar encoding and HIL opt-in."""
import importlib.util
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]


def run_script(name, args=(), env=None):
    clean = {k: v for k, v in os.environ.items() if not k.startswith("RAMEN_HIL_")}
    clean.update(env or {})
    return subprocess.run(["bash", str(ROOT / name), *args], cwd=ROOT, env=clean,
                          capture_output=True, text=True, timeout=30)


class FirmwareTests(unittest.TestCase):
    def test_exact_binary_records_and_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            shim = Path(tmp) / "python-shim"
            shim.mkdir()
            (shim / "sitecustomize.py").write_text(
                "import os, errno\ndef unsupported(fd):\n    raise OSError(errno.EINVAL, 'efivarfs has no fsync')\nos.fsync = unsupported\n")
            env = {"RAMEN_HIL_EFIVAR_DIR": tmp, "PYTHONPATH": str(shim)}
            for slot, byte in [("A", 0), ("B", 1)]:
                result = run_script("tools/hil/set_ramenos_ab_slot.sh", [slot], env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(next(Path(tmp).glob("RamenAbSlot-*")).read_bytes(),
                                 bytes([7, 0, 0, 0, 1, byte, 1]))
            for nonce in ["1", "0123456789abcdef"]:
                result = run_script("tools/hil/set_ramenos_boot_nonce.sh", [nonce], env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(next(Path(tmp).glob("RamenBootNonce-*")).read_bytes(),
                                 bytes([7, 0, 0, 0]) + int(nonce, 16).to_bytes(8, "little"))
            before = next(Path(tmp).glob("RamenBootNonce-*")).read_bytes()
            for nonce in ["0", "-1", "10000000000000000", "unknown"]:
                self.assertNotEqual(run_script("tools/hil/set_ramenos_boot_nonce.sh", [nonce], env).returncode, 0)
                self.assertEqual(next(Path(tmp).glob("RamenBootNonce-*")).read_bytes(), before)


class CiTests(unittest.TestCase):
    def test_non_repository_paths_do_not_receive_prose_exemption(self):
        spec = importlib.util.spec_from_file_location("ci_policy", ROOT / "tools/ci/change_policy.py")
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        for path in ("/tmp/external/AGENTS.md", "../external/CURRENT.md",
                     "docs/../README.md", "./README.md", "docs//note.md",
                     "docs\\note.md", "", "docs/org/../packet.json"):
            with self.subTest(path=path):
                self.assertTrue(policy.requires_foundry([path]), path)
        self.assertFalse(policy.requires_foundry(["README.md", "docs/note.md"]))

    def test_executable_docs_require_foundry_before_prose_exemption(self):
        spec = importlib.util.spec_from_file_location("ci_policy", ROOT / "tools/ci/change_policy.py")
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        for path in ["docs/contracts/editor-native-preview-read-v0.json",
                     "docs/contracts/new-contract.md", "docs/fixtures/new.yaml",
                     "docs/new-executable-input.json", "docs/DESKTOP_EDITOR_WIRE_V1.md",
                     "docs/HIL_APPLIANCE_EVIDENCE_V0.md",
                     "docs/STORE_AUTHORITY_EPOCH_V1.md",
                     "docs/DESKTOP_EDITOR_PROCESS_API_V0.md", "docs/plans/editor-process-v0.md", "CONSTITUTION.md",
                     "EVIDENCE_LEVELS.md", "drivers/reference_vaults/virtio-net/README.md",
                     "drivers/reference_vaults/virtio-blk/README.md"]:
            with self.subTest(path=path):
                self.assertTrue(policy.requires_foundry([path]), path)
        self.assertFalse(policy.requires_foundry([
            "README.md", "CURRENT_STATUS.md", "docs/INDEX.md", "docs/research/RESEARCH_PROGRAM.md",
            "docs/org/current_task.yaml", "docs/org/tasks/new-packet.json"]))

    def test_execution_consumed_markdown_is_not_prose(self):
        spec = importlib.util.spec_from_file_location("ci_policy", ROOT / "tools/ci/change_policy.py")
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        # Audit literal inputs in OS gate tooling. Governance alone owns org
        # packet/prose checks, so its requirements do not activate expensive lanes.
        paths = set()
        for directory in (ROOT / "tools/ci", ROOT / "tools/foundry"):
            for source in directory.iterdir():
                if (source.suffix not in {".py", ".sh"} or source.name.startswith("test_")
                        or source.name in {"change_policy.py", "foundry_org_governance_g0.sh"}):
                    continue
                for line in source.read_text().splitlines():
                    if not line.lstrip().startswith("#"):
                        paths.update(re.findall(r"docs/[A-Za-z0-9_./-]+\.md", line))
                        paths.update(re.findall(r"[\"']([A-Z][A-Z0-9_]*\.md)[\"']", line))
            for registry in directory.glob("*sources*v*.json"):
                paths.update(path for path in json.loads(registry.read_bytes())["paths"]
                             if path.endswith(".md"))
        # Contract source pins can name root documents rather than docs/**.
        # Free-form historical prose references are intentionally not input pins.
        def pinned_markdown(value):
            if type(value) is dict:
                if (type(value.get("path")) is str and value["path"].endswith(".md")
                        and "sha256" in value):
                    paths.add(value["path"])
                for child in value.values():
                    pinned_markdown(child)
            elif type(value) is list:
                for child in value:
                    pinned_markdown(child)
        for contract in (ROOT / "docs/contracts").rglob("*.json"):
            pinned_markdown(json.loads(contract.read_bytes()))
        self.assertIn("CONSTITUTION.md", paths)
        self.assertIn("EVIDENCE_LEVELS.md", paths)
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(policy.requires_foundry([path]), path)

    def test_contract_modification_and_deletion_cli(self):
        for name in ("docs/contracts/editor-native-preview-read-v0.json", "CONSTITUTION.md"):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                def git(*args):
                    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
                git("init", "-q")
                git("config", "user.name", "CI fixture")
                git("config", "user.email", "fixture@example.invalid")
                contract = root / name
                contract.parent.mkdir(parents=True, exist_ok=True)
                contract.write_text('{"version":1}\n')
                git("add", ".")
                git("commit", "-qm", "baseline")
                base = git("rev-parse", "HEAD")
                for operation in ("modify", "delete"):
                    if operation == "modify":
                        contract.write_text('{"version":2}\n')
                    else:
                        contract.unlink()
                    git("add", "-A")
                    git("commit", "-qm", operation)
                    result = subprocess.run(["python3", str(ROOT / "tools/ci/change_policy.py"),
                                             "classify", base, "HEAD"], cwd=root,
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    with self.subTest(path=name, operation=operation):
                        self.assertEqual(result.stdout.strip(), "true", operation)

    def test_classifier_and_merge_fail_closed(self):
        spec = importlib.util.spec_from_file_location("ci_policy", ROOT / "tools/ci/change_policy.py")
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        self.assertFalse(policy.requires_foundry(["README.md", "docs/org/current_task.yaml"]))
        for path in ["tools/hil/build_usb_boot_image.sh", "tools/init/build_init_image.py",
                     "justfile", ".github/workflows/ci.yml", "kernel/src/lib.rs", "new-unknown-file"]:
            self.assertTrue(policy.requires_foundry([path]), path)
        for changes in ["failure", "cancelled", "skipped", ""]:
            self.assertFalse(policy.merge_allowed(changes, "false", "skipped", "success"))
        for output in ["", "bogus"]:
            self.assertFalse(policy.merge_allowed("success", output, "skipped", "success"))
        self.assertTrue(policy.merge_allowed("success", "false", "skipped", "success"))
        self.assertTrue(policy.merge_allowed("success", "true", "success", "success"))
        self.assertFalse(policy.merge_allowed("success", "true", "skipped", "success"))
        self.assertFalse(policy.merge_allowed("success", "false", "skipped", "failure"))
        result = subprocess.run(["python3", str(ROOT / "tools/ci/change_policy.py"), "classify", "no-such-ref", "HEAD"], cwd=ROOT, capture_output=True)
        self.assertNotEqual(result.returncode, 0)


class CiEventTests(unittest.TestCase):
    """Exercise the event CLI with real history, including absent event bases."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "CI fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        for path in ("README.md", "NEXT_TASKS.md", "kernel.rs"):
            (self.root / path).write_text("baseline\n")
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")
        self.base = self.git("rev-parse", "HEAD")
        (self.root / "README.md").write_text("updated prose\n")
        self.git("commit", "-qam", "prose")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root,
                                       stderr=subprocess.DEVNULL).decode().strip()

    def policy(self, *args, cwd=None):
        return subprocess.run([sys.executable, str(ROOT / "tools/ci/change_policy.py"), *args],
                              cwd=cwd or self.root, capture_output=True, text=True, timeout=30)

    def test_pr_and_main_push_use_their_own_base(self):
        for event, valid, unused in (("pull_request", "--pr-base", "--push-base"),
                                     ("push", "--push-base", "--pr-base")):
            with self.subTest(event=event):
                result = self.policy("event", event, valid, self.base, unused, "no-such-ref")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "false\n")
                self.assertIn("Foundry-required changed paths: []", result.stderr)

    def test_new_branch_zero_base_compares_the_complete_tree(self):
        result = self.policy("event", "push", "--push-base", "0" * 40)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "true\n")
        self.assertIn('"kernel.rs"', result.stderr)
        self.assertIn('"NEXT_TASKS.md"', result.stderr)

    def test_missing_null_or_unknown_base_fails_then_valid_base_recovers(self):
        for event, option in (("pull_request", "--pr-base"), ("push", "--push-base")):
            for args in ((), (option, ""), (option, "null"), (option, "no-such-ref")):
                with self.subTest(event=event, args=args):
                    result = self.policy("event", event, *args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
            result = self.policy("event", event, option, self.base)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "false\n")
        result = self.policy("event", "schedule")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_executable_markdown_modify_rename_and_delete_keep_foundry(self):
        for operation in ("modify", "rename", "delete"):
            if operation == "modify":
                (self.root / "NEXT_TASKS.md").write_text("updated contract\n")
            elif operation == "rename":
                (self.root / "NEXT_TASKS.md").rename(self.root / "ordinary.md")
            else:
                (self.root / "ordinary.md").unlink()
            self.git("add", "-A")
            self.git("commit", "-qm", operation)
            with self.subTest(operation=operation):
                result = self.policy("event", "pull_request", "--pr-base", self.base)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "true\n")
                self.assertIn('"NEXT_TASKS.md"', result.stderr)

    def test_branchless_manual_dispatch_requires_fresh_full_lane_results(self):
        # Manual dispatch has no pull_request.base or before. It must not call
        # Git with an empty base, infer prose, or depend on a branch predecessor.
        with tempfile.TemporaryDirectory() as no_git:
            result = self.policy("event", "workflow_dispatch", cwd=no_git)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "true\n")
        self.assertIn("Manual dispatch requests complete Foundry validation", result.stderr)
        classification = result.stdout.strip()
        for lane_result in ("skipped", "failure", "cancelled", "", "success"):
            with self.subTest(lane_result=lane_result):
                foundry = self.policy("foundry", "success", classification,
                                      lane_result, "success", "success", "success", "success")
                expected = lane_result == "success"
                self.assertEqual(foundry.returncode == 0, expected, foundry.stderr)
                merge = self.policy("merge", "success", classification,
                                    "success" if foundry.returncode == 0 else "failure", "success")
                self.assertEqual(merge.returncode == 0, expected, merge.stderr)
        for changes in ("failure", "cancelled", "skipped", ""):
            merge = self.policy("merge", changes, "", "skipped", "success")
            self.assertNotEqual(merge.returncode, 0)

    def test_workflow_shell_publishes_only_successful_event_classification(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        changes = re.search(r"^  changes:\s*\n(.*?)(?=^  [\w-]+:|\Z)",
                            workflow, re.M | re.S).group(1)
        # The final step of this job owns the output. Exercise its actual shell
        # body, including errexit and GITHUB_OUTPUT, with GitHub's empty bases.
        body = re.split(r"(?m)^\s+run:\s*\|\s*\n", changes, maxsplit=1)[1]
        body = textwrap.dedent(body)
        destination = self.root / "tools/ci/change_policy.py"
        destination.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "tools/ci/change_policy.py", destination)
        output = self.root / "github-output"
        for event, pr_base, push_base, expected in (
                ("workflow_dispatch", "", "", "true"),
                ("pull_request", self.base, "", "false"),
                ("push", "", self.base, "false"),
                ("push", "", "0" * 40, "true"),
                ("push", "", "", None),
                ("pull_request", "", "", None)):
            with self.subTest(event=event, pr_base=pr_base, push_base=push_base):
                output.unlink(missing_ok=True)
                env = dict(os.environ, EVENT_NAME=event, PR_BASE=pr_base,
                           PUSH_BASE=push_base, GITHUB_OUTPUT=str(output))
                result = subprocess.run(["bash", "-c", body], cwd=self.root,
                                        env=env, capture_output=True, text=True, timeout=30)
                if expected is None:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text(), f"os_code={expected}\n")


class ApplianceTests(unittest.TestCase):
    def test_opt_in_captures_serial_under_inherited_live_environment(self):
        import pty
        import threading
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        with tempfile.TemporaryDirectory() as tmp:
            stopped = threading.Event()
            def feed():
                while not stopped.wait(0.05):
                    os.write(master, b"RAMEN OS synthetic serial fixture\n")
            thread = threading.Thread(target=feed)
            thread.start()
            try:
                result = run_script("tools/ci/foundry_hil_appliance_s12_4.sh", env={
                    "RAMEN_HIL_APPLIANCE": "1", "RAMEN_HIL_SERIAL_DEV": os.ttyname(slave),
                    "RAMEN_HIL_EVIDENCE_DIR": tmp, "RAMEN_HIL_RUN_ID": "synthetic-capture",
                    "RAMEN_HIL_CAPTURE_TIMEOUT_S": "0.5", "RAMEN_HIL_APPLIANCE_ID": "test-pi",
                })
            finally:
                stopped.set()
                thread.join()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            payload = json.loads((Path(tmp) / "synthetic-capture.json").read_text())
            self.assertEqual(payload["serial_input_kind"], "live_device")
            self.assertGreater(Path(payload["serial_log"]).stat().st_size, 0)
            self.assertEqual(payload["appliance_id"], "test-pi")
            self.assertEqual(payload["evidence_level"], "PASS/HIL-APPLIANCE")
            # The same run ID cannot overwrite valid evidence.
            repeated = run_script("tools/hil/appliance_capture_serial.sh", env={
                "RAMEN_HIL_EVIDENCE_DIR": tmp, "RAMEN_HIL_RUN_ID": "synthetic-capture",
                "RAMEN_HIL_SERIAL_DEV": os.ttyname(slave),
            })
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn("RUN_ID_REUSED", repeated.stderr)


if __name__ == "__main__":
    unittest.main()
