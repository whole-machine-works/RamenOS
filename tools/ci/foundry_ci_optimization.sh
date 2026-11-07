#!/usr/bin/env bash
# Tooling regressions preserve full gate coverage and fresh runtime evidence.
set -euo pipefail
cd "$(dirname "$0")/../.."
python3 tools/ci/test_stage_timer.py
python3 tools/ci/test_broker_gate_once.py
python3 tools/ci/test_ci_lanes.py
python3 tools/ci/test_editor_source_inventory.py
python3 tools/ci/test_build_cache.py
python3 tools/ci/test_dev_check.py
python3 tools/ci/test_dev_recipe.py
python3 tools/ci/test_cargo_artifact.py
python3 tools/ci/test_store_test_dependencies.py
python3 tools/ci/test_acceptance_build.py
python3 tools/ci/test_test_timing.py
python3 tools/ci/test_compiler_cache_control.py
python3 tools/ci/test_build_streamlining.py
python3 tools/ci/test_selected_test_runner.py
python3 tools/ci/test_editor_process_preparation.py
python3 tools/ci/test_editor_process_linux_prerequisites.py
python3 tools/ci/test_editor_process_p0.py
python3 tools/ci/test_editor_process_recording.py
python3 tools/ci/test_editor_process_source_policy.py
python3 -m unittest discover -s tools/ci -p "test_editor_process_reader*.py"
python3 tools/ci/test_editor_process_parent_join.py
python3 tools/ci/test_editor_process_stage_receipts.py
python3 tools/ci/test_qemu_boot_observation.py
python3 tools/trace/test_boot_profile_inputs.py
python3 tools/trace/test_boot_profile_capture.py
python3 tools/trace/test_run0_rsp.py
python3 tools/trace/test_run0_rsp_capability.py
python3 tools/trace/test_run0_host_cpu_reader.py
python3 tools/trace/test_run0_host_cpu_witness.py
python3 tools/trace/test_run0_c0_paging.py
python3 tools/trace/test_run0_c0_decode.py
python3 tools/trace/test_run0_c0_wire.py
python3 tools/trace/test_run0_c0_rsp.py
python3 tools/trace/test_run0_c0_entry.py
python3 tools/trace/test_run0_c0_entry_stop.py
python3 tools/trace/test_run0_c0_acquire.py
python3 tools/trace/test_run0_c0_host.py
python3 tools/trace/test_run0_c0_budget.py
python3 tools/trace/test_run0_c0_wire_owned.py
python3 tools/trace/test_run0_c0_capture.py
python3 tools/trace/test_run0_c0_runtime.py
python3 -B tools/trace/test_run0_call_owner.py
python3 -B tools/trace/test_run0_call_budget.py
python3 -B tools/trace/test_run0_call_read.py
cargo test --locked -p idl_codegen --test content_stable
printf '%s\n' 'FOUNDRY_CI_OPTIMIZATION: PASS scope=tooling'
