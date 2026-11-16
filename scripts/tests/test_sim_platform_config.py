#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Evaluate actual SIM Kbuild selection with handset and generic VM configs.

Runs GNU Make only to report object lists; does not compile or recurse into Kbuild.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--make', default='make')
    parser.add_argument('--vm-config', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    kernel = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    baseline = kernel / 'arch/arm64/configs/merge_kirin970_defconfig'
    vm = args.vm_config.resolve()
    assert 'CONFIG_HISILICON_PLATFORM=y' in baseline.read_text().splitlines()
    assert '# CONFIG_HISILICON_PLATFORM is not set' in vm.read_text().splitlines()
    # Disabled config symbols must not leak in from the calling shell/Make.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith('CONFIG_') and
           k not in ('MAKEFLAGS', 'GNUMAKEFLAGS', 'MAKEFILES', 'MFLAGS')}
    cases = [
        ('baseline', baseline, '', True),
        ('baseline-platform-off', baseline, 'CONFIG_HISILICON_PLATFORM := n\n', False),
        ('generic-unset', vm, '', False),
        ('generic-explicit-n', vm, 'CONFIG_HISILICON_PLATFORM := n\n', False),
        ('generic-platform-on', vm, 'CONFIG_HISILICON_PLATFORM := y\n', True),
        ('generic-pmic-only', vm, 'CONFIG_HISI_PMIC_PMU_SPMI := y\n', False),
    ]
    results = []
    for name, config, overrides, selected in cases:
        wrapper = output / (name + '.mk')
        wrapper.write_text(f'''include {config}
{overrides}include {kernel / 'drivers/Makefile'}
root_y := $(strip $(obj-y))
root_m := $(strip $(obj-m))
obj-y :=
obj-m :=
ifneq ($(filter hisi_sim_adapt/,$(root_y)),)
include {kernel / 'drivers/hisi_sim_adapt/Makefile'}
endif
.PHONY: report
report:
\t@printf '%s\\n' 'builtins=$(root_y)' 'modules=$(root_m)' 'sim_objects=$(strip $(obj-y))' 'platform=$(CONFIG_HISILICON_PLATFORM)'
''')
        command = [args.make, '-rR', '--no-print-directory', '-s', '-f', str(wrapper), 'report']
        run = subprocess.run(command, cwd=kernel, env=env, text=True,
                             capture_output=True, timeout=15)
        (output / (name + '.log')).write_text(run.stdout + run.stderr)
        values = dict(line.split('=', 1) for line in run.stdout.splitlines() if '=' in line)
        y, m = values.get('builtins', '').split(), values.get('modules', '').split()
        child = values.get('sim_objects', '').split()
        passed = (run.returncode == 0 and y.count('hisi_sim_adapt/') == int(selected)
                  and 'hisi_sim_adapt/' not in m
                  and child == (['hisi_sim_adapt.o'] if selected else []))
        results.append({'case': name, 'config': str(config), 'overrides': overrides,
                        'command': command, 'exit_status': run.returncode,
                        'expected_sim_selected': selected, 'values': values, 'passed': passed})
        print(name, 'PASS' if passed else 'FAIL', flush=True)
    # Changing this platform flag may only change its two top-level directories.
    for left, right in ((0, 1), (4, 2)):
        without_platform = lambda text: [x for x in text.split()
                                         if x not in ('hisi/', 'hisi_sim_adapt/')]
        assert without_platform(results[left]['values']['builtins']) == without_platform(
            results[right]['values']['builtins'])
        assert results[left]['values']['modules'] == results[right]['values']['modules']
    paths = [baseline, vm, kernel / 'drivers/Makefile',
             kernel / 'drivers/hisi_sim_adapt/Makefile', kernel / 'drivers/hisi/Kconfig']
    receipt = {'inputs': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
               'results': results, 'unrelated_object_lists_unchanged_by_platform_toggle': True,
               'make_version': subprocess.check_output([args.make, '--version'], text=True),
               'limits': 'Actual Makefile selection and child object list only; counterfactual flags are local fixture variables, not configured kernel builds or hardware results.'}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return int(not all(result['passed'] for result in results))


if __name__ == '__main__':
    raise SystemExit(main())
