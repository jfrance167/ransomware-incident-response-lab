import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
USE_PATTERN = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)


class RepositoryPolicyTests(unittest.TestCase):
    def test_actions_are_pinned(self):
        for path in WORKFLOWS.glob("*.yml"):
            for action in USE_PATTERN.findall(path.read_text(encoding="utf-8")):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$", f"unpinned action in {path.name}")

    def test_checkout_does_not_persist_credentials(self):
        for path in WORKFLOWS.glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            if "actions/checkout@" in text:
                self.assertIn("persist-credentials: false", text)

    def test_workflows_use_minimum_permissions(self):
        for path in WORKFLOWS.glob("*.yml"):
            self.assertIn("permissions:", path.read_text(encoding="utf-8"))

    def test_security_workflows_support_manual_dispatch(self):
        for name in ("bandit.yml", "codeql.yml"):
            self.assertIn("workflow_dispatch:", (WORKFLOWS / name).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
