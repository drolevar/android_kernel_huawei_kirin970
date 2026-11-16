#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Evaluate calibration, NV provider and fuel-gauge caller Kbuild paths.

Use actual parent/child Makefiles and handset/VM configs; report object lists
only. No compilation, Kbuild recursion or edits to supplied configs.
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
    assert 'CONFIG_HUAWEI_PLATFORM=y' in baseline.read_text().splitlines()
    assert 'CONFIG_HUAWEI_COUL=y' not in baseline.read_text().splitlines()
    assert '# CONFIG_HUAWEI_PLATFORM is not set' in vm.read_text().splitlines()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith('CONFIG_') and
           k not in ('MAKEFLAGS', 'GNUMAKEFLAGS', 'MAKEFILES', 'MFLAGS')}
    # Ordered traversal of the actual directories needed for these contracts.
    nodes = [
        ('root', 'drivers', None, None),
        ('power', 'drivers/hwpower', 'root', 'hwpower/'),
        ('coul', 'drivers/hwpower/cc_coul', 'power', 'cc_coul/'),
        ('vendor', 'drivers/huawei_platform', 'root', 'huawei_platform/'),
        ('vendor_power', 'drivers/huawei_platform/hwpower', 'vendor', 'hwpower/'),
        ('common', 'drivers/huawei_platform/hwpower/common_module', 'vendor_power', 'common_module/'),
        ('nv', 'drivers/huawei_platform/hwpower/common_module/power_nv', 'common', 'power_nv/'),
        ('ic', 'drivers/hwpower/cc_hardware_ic', 'power', 'cc_hardware_ic/'),
        ('fuel', 'drivers/hwpower/cc_hardware_ic/fuel_gauge', 'ic', 'fuel_gauge/'),
        ('bq', 'drivers/hwpower/cc_hardware_ic/fuel_gauge/bq27z561', 'fuel', 'bq27z561/'),
        ('rt', 'drivers/hwpower/cc_hardware_ic/fuel_gauge/rt9426', 'fuel', 'rt9426/'),
    ]
    cases = [
        ('baseline', baseline, '', True, False, False),
        ('baseline-coul-on', baseline, 'CONFIG_HUAWEI_COUL := y\n', True, True, False),
        ('baseline-platform-off', baseline, 'CONFIG_HUAWEI_PLATFORM := n\n', False, False, False),
        ('generic-unset', vm, '', False, False, False),
        ('generic-explicit-n', vm, 'CONFIG_HUAWEI_PLATFORM := n\n', False, False, False),
        ('generic-platform-on', vm, 'CONFIG_HUAWEI_PLATFORM := y\n', True, False, False),
        ('generic-coul-only', vm, 'CONFIG_HUAWEI_COUL := y\n', False, True, False),
        ('baseline-fuel-callers', baseline,
         'CONFIG_FUEL_GAUGE := y\nCONFIG_BQ27Z561_FUEL_GAUGE := y\nCONFIG_RT9426_FUEL_GAUGE := y\n',
         True, False, True),
    ]
    results = []
    for name, config, overrides, selected, coul, fuel in cases:
        lines = [f'include {config}', overrides]
        for label, directory, parent, entry in nodes:
            lines += ['obj-y :=', 'obj-m :=', 'obj-n :=']
            if parent:
                lines += [f'ifneq ($(filter {entry},$({parent}_y)),)']
            lines += [f'include {kernel / directory / "Makefile"}']
            if parent:
                lines += ['endif']
            lines += [f'{label}_y := $(strip $(obj-y))', f'{label}_m := $(strip $(obj-m))']
        lines += ['.PHONY: report', 'report:', "\t@printf '%s\\n' " + ' '.join(
            f"'{label}_{kind}=$({label}_{kind})'" for label, *_ in nodes for kind in ('y', 'm'))]
        wrapper = output / (name + '.mk')
        wrapper.write_text('\n'.join(lines) + '\n')
        command = [args.make, '-rR', '--no-print-directory', '-s', '-f', str(wrapper), 'report']
        run = subprocess.run(command, cwd=kernel, env=env, capture_output=True, text=True, timeout=15)
        (output / (name + '.log')).write_text(run.stdout + run.stderr)
        values = dict(line.split('=', 1) for line in run.stdout.splitlines() if '=' in line)
        expected_coul = (['coul_interface.o', 'coul_test.o', 'coul_sysfs.o'] if coul else [])
        if selected:
            expected_coul += ['coul_calibration.o']
        passed = (run.returncode == 0 and values.get('coul_y', '').split() == expected_coul
                  and values.get('coul_m') == '' and values.get('nv_m') == ''
                  and values.get('nv_y', '').split() == (['power_nv.o'] if selected else [])
                  and values.get('bq_y', '').split() == (['bq27z561.o'] if fuel else [])
                  and values.get('rt_y', '').split() == (['rt9426.o'] if fuel else []))
        results.append({'case': name, 'config': str(config), 'overrides': overrides,
                        'command': command, 'exit_status': run.returncode,
                        'expected_calibration_and_provider': selected, 'values': values, 'passed': passed})
        print(name, 'PASS' if passed else 'FAIL', flush=True)
    paths = [baseline, vm] + [kernel / directory / 'Makefile' for _, directory, *_ in nodes]
    receipt = {'inputs': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
               'results': results,
               'make_version': subprocess.check_output([args.make, '--version'], text=True),
               'limits': 'Actual Make selection only. Counterfactual overrides are test variables, not validated Kconfig combinations. Platform-off fuel-gauge configurations still need a broader dependency audit.'}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return int(not all(result['passed'] for result in results))


if __name__ == '__main__':
    raise SystemExit(main())
