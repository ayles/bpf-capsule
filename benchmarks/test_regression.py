#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Focused tests for the cross-run regression policy."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("regression.py")
SPEC = importlib.util.spec_from_file_location("bpf_capsule_regression", MODULE_PATH)
assert SPEC and SPEC.loader
regression = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = regression
SPEC.loader.exec_module(regression)


def metric(value: float, unit: str = "ms") -> dict:
    return {"median": value, "unit": unit}


def report(metrics: dict) -> dict:
    return {
        "profile": "5.15",
        "selection": [],
        "tests": {"workload": {"metrics": metrics, "objects": {}}},
    }


class CompareTest(unittest.TestCase):
    def compare(self, current: dict, baseline: dict) -> tuple[list[str], list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory) / "baseline.json"
            baseline_path.write_text(json.dumps(baseline))
            return regression.compare(current, baseline_path)

    def test_timing_changes_are_reported_but_never_gate_correctness(self) -> None:
        baseline = report({"kernel_ms": metric(1), "native_ms": metric(1)})
        current = report({"kernel_ms": metric(2), "native_ms": metric(0.5)})

        failures, observations = self.compare(current, baseline)
        self.assertEqual(failures, [])
        self.assertEqual(len(observations), 2)
        self.assertTrue(all("workload." in item for item in observations))

    def test_one_byte_executable_code_change_fails(self) -> None:
        baseline = report({})
        current = report({})
        baseline["tests"]["workload"]["objects"] = {
            "program.o": {"code_bytes": 1000, "file_bytes": 2000},
        }
        current["tests"]["workload"]["objects"] = {
            "program.o": {"code_bytes": 1001, "file_bytes": 2000},
        }

        failures, observations = self.compare(current, baseline)
        self.assertEqual(observations, [])
        self.assertEqual(len(failures), 1)
        self.assertIn("program.o.code_bytes", failures[0])

    def test_canonical_improvement_requires_baseline_update(self) -> None:
        baseline = report({"jit_bytes": metric(1000, "bytes")})
        current = report({"jit_bytes": metric(999, "bytes")})

        failures, observations = self.compare(current, baseline)
        self.assertEqual(observations, [])
        self.assertEqual(len(failures), 1)
        self.assertIn("jit_bytes", failures[0])

    def test_debug_metadata_growth_does_not_fail_program_size_gate(self) -> None:
        baseline = report({})
        current = report({})
        baseline["tests"]["workload"]["objects"] = {
            "program.o": {"code_bytes": 1000, "file_bytes": 2000},
        }
        current["tests"]["workload"]["objects"] = {
            "program.o": {"code_bytes": 1000, "file_bytes": 4000},
        }

        self.assertEqual(self.compare(current, baseline), ([], []))

    def test_object_hash_change_fails_even_when_sizes_match(self) -> None:
        baseline = report({})
        current = report({})
        baseline["tests"]["workload"]["objects"] = {
            "program.o": {"sha256": "old", "code_bytes": 1000},
        }
        current["tests"]["workload"]["objects"] = {
            "program.o": {"sha256": "new", "code_bytes": 1000},
        }

        failures, observations = self.compare(current, baseline)
        self.assertEqual(observations, [])
        self.assertEqual(len(failures), 1)
        self.assertIn("program.o.sha256", failures[0])

    def test_one_verifier_instruction_change_fails(self) -> None:
        baseline = report({"verifier_processed_insns": metric(1000, "insns")})
        current = report({"verifier_processed_insns": metric(1001, "insns")})

        failures, observations = self.compare(current, baseline)
        self.assertEqual(observations, [])
        self.assertEqual(len(failures), 1)
        self.assertIn("verifier_processed_insns", failures[0])

    def test_any_verifier_expansion_change_fails(self) -> None:
        baseline = report({"verifier_expansion": metric(4.0, "ratio")})
        current = report({"verifier_expansion": metric(4.01, "ratio")})

        failures, observations = self.compare(current, baseline)
        self.assertEqual(observations, [])
        self.assertEqual(len(failures), 1)
        self.assertIn("verifier_expansion", failures[0])


class TargetPolicyTest(unittest.TestCase):
    def case(self, name: str, profile: str = "6.9") -> regression.Case:
        args = regression.argparse.Namespace(
            profile=profile,
            doom_wad=Path("doom.wad"),
            doom_frames=1,
            llama2_model=None,
            llama2q_model=None,
        )
        return next(case for case in regression.make_cases(Path("build"), args)
                    if case.name == name)

    def doom_case(self, profile: str) -> regression.Case:
        return self.case("doom", profile)

    def test_doom_reports_kernel_frame_percentiles_repeatably(self) -> None:
        case = self.doom_case("6.9")
        self.assertIsNotNone(case.repeatability_dir)
        recorded = {name for metric in case.metrics
                    for name, _unit in metric.groups}
        self.assertLessEqual({"kernel_ms", "p99_ms", "max_ms",
                              "measured_frames"}, recorded)

    def test_version_granular_profiles(self) -> None:
        self.assertEqual(regression.kernel_version("5.15"), "5.15")
        self.assertEqual(regression.kernel_version("6.6"), "6.6")
        self.assertEqual(regression.kernel_version("7.1"), "7.1")
        for invalid in ("5.14", "6", "v6.9", "6.1000"):
            with self.assertRaises(regression.argparse.ArgumentTypeError):
                regression.kernel_version(invalid)

    def test_continuation_stress_is_not_a_zero_drain_workload(self) -> None:
        self.assertIsNone(self.case("compiler-core").max_drains)
        for name in (
            "zlib",
            "wasm3-zlib",
            "lua",
            "quickjs",
            "sqlite",
        ):
            case = self.case(name)
            self.assertEqual(case.max_drains, 0, name)
            recorded = {field for metric in case.metrics for field, _unit in metric.groups}
            self.assertIn("drains", recorded, name)

    def test_drive_contract_is_executed(self) -> None:
        case = self.case("drive-contract")
        self.assertEqual(
            case.command,
            ["build/tests/errors/drive_contract_host"],
        )
        self.assertEqual(case.marker, "DRIVE-CONTRACT-PASS")

    def test_lua_steady_state_is_measured_without_duplicating_its_object(self) -> None:
        case = self.case("lua-xdp-steady")
        self.assertEqual(case.objects, [])
        self.assertTrue(any(group[0] == "kernel_ms"
                            for metric in case.metrics
                            for group in metric.groups))

    def test_load_timing_is_a_suite_metric_examples_never_print_it(self) -> None:
        # Example hosts are pure API demonstrations: they load with plain
        # libbpf and report only kernel execution time. The load-timing print
        # comes from the suite-only test header, so only suite hosts may be
        # expected to produce it.
        examples = {"fib", "standalone-expression", "zlib", "wasm3-zlib",
                    "lua", "quickjs", "sqlite", "rust", "llama2",
                    "llama2-q8", "doom"}
        probed = {"zlib", "wasm3-zlib", "lua", "quickjs", "sqlite",
                  "rust", "llama2", "llama2-q8", "doom"}
        exempt = {"compiler-core", "lua-xdp-steady", "error-strings",
                  "drive-contract"}
        for case in regression.make_cases(Path("build"), regression.argparse.Namespace(
                profile="6.9", doom_wad=None, doom_frames=1,
                llama2_model=None, llama2q_model=None)):
            recorded = {
                name
                for metric in case.metrics
                for name, _unit in metric.groups
            }
            if case.name in examples:
                self.assertFalse({"load_s", "load_ms"} & recorded, case.name)
                self.assertEqual(case.verifier_probe, case.name in probed)
            elif case.name not in exempt and case.objects:
                self.assertTrue({"load_s", "load_ms"} & recorded, case.name)
        self.assertTrue(self.case("lua-xdp").verifier_probe)


class ArtifactLayoutTest(unittest.TestCase):
    def test_packaged_artifact_wins_when_staged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            packaged = build / "examples/lua/lua"
            packaged.parent.mkdir(parents=True)
            packaged.write_text("runner")
            local = build / "examples/lua/lua/lua"

            self.assertEqual(
                regression.packaged_or_local(
                    build, "examples/lua/lua", local),
                packaged,
            )

    def test_local_artifact_is_the_developer_build_fallback(self) -> None:
        build = Path("build")
        local = build / "examples/lua/lua/lua"

        self.assertEqual(
            regression.packaged_or_local(
                build, "examples/lua/lua", local),
            local,
        )

    def test_verifier_probe_is_found_from_nested_local_lua_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            probe = build / "tests/verifier-metrics/verifier_load_probe"
            probe.parent.mkdir(parents=True)
            probe.write_text("probe")
            lua_object = build / "examples/lua/lua/lua_bpf.o"
            lua_object.parent.mkdir(parents=True)
            lua_object.write_text("object")

            self.assertEqual(
                regression.find_build_artifact(
                    lua_object, Path("tests/verifier-metrics/verifier_load_probe")
                ),
                probe,
            )

    def test_lua_cases_use_the_staged_installed_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            for relative in (
                "examples/lua/lua",
                "examples/lua/lua_bpf.o",
                "examples/lua/script.lua",
                "examples/lua-xdp/lua_xdp_bpf.o",
                "examples/lua-xdp/packet_filter.lua",
                "examples/lua-xdp/packet_observer.lua",
            ):
                artifact = build / relative
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text(relative)
            args = regression.argparse.Namespace(
                profile="6.9",
                doom_wad=None,
                doom_frames=1,
                llama2_model=None,
                llama2q_model=None,
            )
            cases = {case.name: case
                     for case in regression.make_cases(build, args)}

            self.assertEqual(
                cases["lua"].command,
                [str(build / "examples/lua/lua"),
                 str(build / "examples/lua/script.lua")],
            )
            self.assertEqual(
                cases["lua"].objects,
                [build / "examples/lua/lua_bpf.o"],
            )
            self.assertEqual(
                cases["lua-xdp"].command[1:],
                [str(build / "examples/lua-xdp/packet_filter.lua"),
                 str(build / "examples/lua-xdp/packet_observer.lua")],
            )
            self.assertEqual(
                cases["lua-xdp"].objects,
                [build / "examples/lua-xdp/lua_xdp_bpf.o"],
            )
            self.assertEqual(
                cases["lua-xdp-steady"].command[1],
                str(build / "examples/lua-xdp/packet_filter.lua"),
            )


class MetricParsingTest(unittest.TestCase):
    def test_yield_delta_may_be_negative_under_timer_noise(self) -> None:
        case = regression.Case(
            "yield", [], "YIELD-PASS", [], [regression.YIELD_COST]
        )
        parsed = regression.parse_metrics(
            case,
            "yield benchmark: 490 ns yielded, 506 ns baseline, "
            "8 round trips, -2.0 ns/round-trip delta",
        )

        self.assertEqual(parsed["round_trip_delta_ns"], (-2.0, "ns"))


class MetadataTest(unittest.TestCase):
    def test_git_commands_trust_only_the_staged_source(self) -> None:
        self.assertEqual(
            regression.git_command("git", "status", "--porcelain"),
            ["git", "-c", f"safe.directory={regression.ROOT}",
             "status", "--porcelain"],
        )


if __name__ == "__main__":
    unittest.main()
