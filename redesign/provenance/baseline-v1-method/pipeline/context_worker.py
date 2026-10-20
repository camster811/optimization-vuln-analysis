"""Extract from one public ELF and localization address; reads no source or oracle inputs."""
import argparse
import os
from pathlib import Path
import re
import subprocess

from .bundles import apply_budget, empty_bundle, normalize, policy_check, validate
from .inventory import ROOT, digest, read_json, require


def engine_home(policy):
    value = os.environ.get('GHIDRA_HOME')
    require(value, 'Set GHIDRA_HOME to the pinned Ghidra installation')
    home = Path(value).expanduser().resolve()
    launcher = home / 'support/analyzeHeadless'
    require(launcher.is_file() and os.access(launcher, os.X_OK), 'Missing Ghidra launcher')
    properties = (home / 'Ghidra/application.properties').read_text()
    require(re.findall(r'^application\.version=(\S+)\s*$', properties, re.M)
            == [policy['ghidra_version']], 'Ghidra version differs from context policy')
    return home


def extract(binary, entry, policy, work, script_directory=None):
    policy_check(policy)
    work.mkdir(parents=True, exist_ok=False)
    output = work / 'raw.json'
    script_directory = script_directory or ROOT / 'ghidra'
    trace = {'input_sha256': digest(binary), 'entry_address': entry, 'error': None}
    try:
        home = engine_home(policy)
    except (OSError, ValueError) as error:
        trace['error'] = str(error)
        return empty_bundle(entry, 'engine_unavailable'), trace
    profile = work / 'profile'
    profile.mkdir()
    settings = {'user.home': profile, 'application.settingsdir': work / 'settings',
                'application.cachedir': work / 'cache', 'application.tempdir': work / 'tmp'}
    # Do not inherit arbitrary Java agents/options into this extraction process.
    # Independent process namespaces can reuse PIDs while sharing /tmp. HotSpot's perf-data
    # file warnings otherwise corrupt Ghidra LaunchSupport's stdout-based JVM probing.
    environment = {**os.environ, 'JAVA_TOOL_OPTIONS': '-XX:-UsePerfData ' +
                   ' '.join(f'-D{k}={v}' for k, v in settings.items())}
    command = [str(home / 'support/analyzeHeadless'), str(work), 'context',
               '-processor', policy['language'], '-cspec', policy['compiler_spec'],
               '-import', str(binary), '-scriptPath', str(script_directory),
               '-loader-loadLibraries', 'false',
               '-max-cpu', '2', '-analysisTimeoutPerFile', str(policy['analysis_timeout_seconds']),
               '-deleteProject', '-log', str(work / 'headless.log'), '-scriptlog', str(work / 'script.log'),
               '-preScript', 'ConfigurePublicAnalysis.java',
               '-postScript', 'ExtractBundle.java', entry, str(output),
               *[str(policy[k]) for k in ('decompiler_timeout_seconds', 'max_functions', 'max_instructions',
                                          'max_data_bytes', 'max_data_bytes_per_reference', 'unknown_data_window_bytes')],
               str(policy['allow_assembly_only']).lower()]
    trace['command'] = command
    try:
        with (work / 'console.log').open('w') as stream:
            result = subprocess.run(command, env=environment, stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=policy['process_timeout_seconds'])
        trace['exit_code'] = result.returncode
        if result.returncode != 0 or not output.is_file():
            trace['error'] = 'Engine failed or did not produce a record'
            return empty_bundle(entry, 'engine_failed'), trace
        raw = normalize(read_json(output))
        validate(raw, binary)
        require(raw['entry_address'] == entry, 'Engine exported a different entry')
        bundle = apply_budget(raw, policy)
        validate(bundle, binary)
        return bundle, trace
    except (subprocess.SubprocessError, OSError) as error:
        trace['error'] = str(error)
        return empty_bundle(entry, 'engine_failed'), trace
    except Exception as error:
        trace['error'] = str(error)
        reason = 'metadata_leakage' if 'metadata' in str(error).lower() else 'invalid_export'
        return empty_bundle(entry, reason), trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--entry', required=True)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    from .bundles import address, canonical
    from .inventory import encode
    address(args.entry)
    bundle, trace = extract(args.input.resolve(), args.entry, read_json(args.policy), args.work.resolve())
    args.output.write_text(canonical(bundle))
    (args.work / 'worker.json').write_text(encode(trace))


if __name__ == '__main__':
    main()
