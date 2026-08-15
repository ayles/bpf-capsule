# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[2] / "benchmarks/matrix.py"
SPEC = importlib.util.spec_from_file_location("bpf_capsule_matrix", SOURCE)
assert SPEC and SPEC.loader
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


class MatrixTest(unittest.TestCase):
    def test_staging_is_complete_and_uses_json_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            package = root / "package"
            stage = root / "stage"
            for relative in (
                "benchmarks/regression.py",
                "tests/vm/guest.py",
                "examples/quickjs/script.js",
            ):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative)
            artifacts = (
                "tests/example/host",
                "examples/lua/lua",
                "examples/lua/lua_bpf.o",
                "examples/lua/script.lua",
                "examples/lua-xdp/lua_xdp_bpf.o",
                "examples/lua-xdp/packet_filter.lua",
                "examples/lua-xdp/packet_observer.lua",
                "tests/errors/error_strings_host",
                "tests/errors/drive_contract_host",
                "tests/verifier-metrics/verifier_load_probe",
            )
            for artifact in artifacts:
                path = package / "libexec/bpf-capsule" / artifact
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(artifact)
            metadata = root / "metadata.json"
            metadata.write_text("{}\n")
            environment = {
                "DOOM_WAD": "none",
                "LLAMA2_MODEL": "none",
                "LLAMA2Q_MODEL": "none",
            }
            with (mock.patch.object(matrix, "ROOT", source),
                  mock.patch.object(
                      matrix, "REGRESSION", source / "benchmarks/regression.py"),
                  mock.patch.object(matrix, "ARTIFACTS", artifacts),
                  mock.patch.dict(os.environ, environment, clear=False)):
                matrix.stage_profile(
                    "6.9", package, stage, "6.9.json", 1.25,
                    metadata, None)
            arguments = json.loads((stage / "config.json").read_text())
            self.assertIn("/tmp/shared/build", arguments)
            self.assertFalse((stage / artifacts[0]).exists())
            self.assertTrue((stage / "build" / artifacts[0]).is_file())
            self.assertTrue((stage / "guest.py").is_file())
            self.assertTrue(
                (stage / "build/examples/lua/script.lua").is_file())
            self.assertTrue(
                (stage / "build/examples/lua-xdp/packet_observer.lua").is_file())
            self.assertTrue(
                (stage / "build/tests/errors/error_strings_host").is_file())
            self.assertTrue(
                (stage / "build/tests/errors/drive_contract_host").is_file())
            self.assertTrue(
                (stage / "build/tests/verifier-metrics/verifier_load_probe").is_file())
            self.assertTrue((stage / "examples/quickjs/script.js").is_file())

    def test_installed_artifact_contract_covers_lua_and_error_hosts(self) -> None:
        required = {
            "examples/lua/lua",
            "examples/lua/lua_bpf.o",
            "examples/lua/script.lua",
            "examples/lua-xdp/lua_xdp_bpf.o",
            "examples/lua-xdp/packet_filter.lua",
            "examples/lua-xdp/packet_observer.lua",
            "tests/errors/error_strings_host",
            "tests/errors/drive_contract_host",
            "tests/verifier-metrics/verifier_load_probe",
        }
        self.assertTrue(required <= set(matrix.ARTIFACTS))
        self.assertNotIn("examples/lua/lua/lua", matrix.ARTIFACTS)

    def test_newest_baseline_ignores_incomplete_and_failed_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "current"
            current.mkdir()

            def report(directory: str, status: str | None, age: int) -> Path:
                path = root / directory
                path.mkdir()
                (path / "matrix-pass").touch()
                contents = {"schema": 3}
                if status:
                    contents["comparison"] = {"status": status}
                for profile, _, _ in matrix.PROFILES:
                    target = path / f"{profile}.json"
                    target.write_text(json.dumps(contents))
                    os.utime(target, (age, age))
                return path

            older = report("older", "pass", 10)
            report("failed", "fail", 30)
            newer = report("newer", None, 20)
            self.assertEqual(matrix.newest_baseline(root, current), newer)
            self.assertNotEqual(matrix.newest_baseline(root, current), older)

    def test_explicit_cpu_ranges_are_normalized(self) -> None:
        with mock.patch.dict(os.environ,
                             {"BPF_CAPSULE_VM_CPUS": "5,1-3,2"}, clear=False):
            self.assertEqual(matrix.selected_cpus(), [1, 2, 3, 5])

    def test_store_source_is_never_reopened_as_git(self) -> None:
        store = "/nix/store/0123456789-source"
        self.assertEqual(matrix.normalize_nix_source(store), f"path:{store}")
        self.assertEqual(matrix.normalize_nix_source(f"git+file://{store}"),
                         f"path:{store}")
        self.assertEqual(matrix.normalize_nix_source(f"path:{store}"),
                         f"path:{store}")

    def test_comparison_failure_is_distinct_from_workload_failure(self) -> None:
        self.assertTrue(matrix.comparison_failed(
            {"comparison": {"status": "fail"}}))
        self.assertFalse(matrix.comparison_failed(
            {"comparison": {"status": "pass"}}))
        self.assertFalse(matrix.comparison_failed({}))


if __name__ == "__main__":
    unittest.main()
