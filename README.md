# OS Benchmarking Tool

More specifically a CLI app that is both an audit runner for OS level probes 
and tests, and report data manager.  The original intent is auditing security 
hardening benchmarks like CIS but with customization flexiblity. This reads a 
collection of probes defined in a YAML file and writes the results to a JSON 
file by default, stdout support is a basic display of the JSON on the CLI.

## MVP Status

The primary goal is to provide structured JSON output for security hardening 
tests with enough metadata to be useful, this has been achieved.  See the 
roadmap below for what other features may make it in before I move on to 
something else.

# Usage

Requires Python 3.11 and is easiest run with Poetry installed using the script entrypoint `cis`.

```bash
Usage: cis [OPTIONS]

  A CIS OS benchmarking app, with flexible configuration and output options.

  Results are `true` if the test passed, and `false` if the test failed.

Options:
  --yaml_file TEXT                YAML file to read
  --full_output                   Full CLI output of the probes
  -q, --quiet                     Quiet mode only writes
  --output_file TEXT              Output file to write to the file
  --remote_audit_storage TEXT     Remote audit storage location (S3)
  --output_file TEXT              Filename to write the audit report to
  --ssh_remote_location TEXT      Remote location to run the probes using SSH.
  --ssm_remote_location TEXT      Remote location to run the probes using AWS
                                  SSM.
  -l, --list_probes               List all probes
  -hl, --hardening_level INTEGER  Hardening level to apply
  -d, --debug                     Debug mode
  --help                          Show this message and exit.
  ```

The output of and audit run will look like this in the JSON file:

```json
$ cat audit_report.json
{
  "metadata": {
    "description": "CIS OS benchmarking report",
    "date": "2024-12-29 02:55:16",
    "user": "anon",
    "total_probes": 27,
    "total_passed": 12,
    "total_errors": 0,
    "total_skipped_probes": 0,
    "hardening_level": 1,
    "remote_log_storage": "audit_report.json",
    "output_file": "audit_report.json",
    "yaml_file": "probes.yaml",
    "audited_system": "Linux-5.14.0-503.19.1.el9_5.x86_64-x86_64-with-glibc2.34"
  },
  "1.1.1 - Disable Unused Filesystems": {
    "1.1.1.1.1": {
      "description": "modprobe cramfs",
      "result": true
    },
    "1.1.1.1.2": {
      "description": "lsmod cramfs",
      "result": true
    },
```

The YAML file looks something like this:

```YAML
metadata:
  system: "Linux"
  benchmark: "CIS RHEL 7 Benchmark"
probes:
  - section_name: "1.1.1"
    description: "Ensure Unused Filesystems are disabled"
    tags: 
      - "filesystems"
      - "low_risk"
    probes:
    # cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat
      - subsection_name: "1.1.1.1.1"
        description: "modprobe cramfs"
        level: 0
        command: "modprobe -n -v cramfs"
        expected: "modprobe: FATAL: Module cramfs not found in directory"
      - subsection_name: "1.1.1.1.2"
        description: "lsmod cramfs"
        level: 0
        command: "lsmod | grep cramfs"
        expected: "--grep-negative"
```

# ROADMAP

-[x] Read YAML defined sets of os hardening tests
-[x] Output results in a JSON file
-[x] Provide metadata and structure to provide a complete audit report
-[ ] Remote audit report storage
-[ ] Remote execution over SSH
-[ ] Remote execution over SSM
-[ ] Expand library of YAML files