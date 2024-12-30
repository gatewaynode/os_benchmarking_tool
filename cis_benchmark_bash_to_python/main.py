"""
A CIS OS benchmarking app, with flexible configuration and output options.

Results are `true` if the test passed, and `false` if the test failed.
"""

import platform
import os
import datetime
import subprocess
import yaml
import click
import json
import logging
from pprint import pprint

# Set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.WARNING)

# Probe report global variable
report = {
    "metadata": {
        "description": "CIS OS benchmarking report",
        "date": "{:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.now()),
        "user": os.getlogin(),
        "total_probes": 0,
        "total_passed": 0,
        "total_errors": 0,
        "total_skipped_probes": 0,
    }
}


def read_yaml_file(yaml_file):
    """Read the YAML file and return as a parsed object"""
    with open(yaml_file, "r") as file:
        try:
            return yaml.safe_load(file)
        except yaml.YAMLError as exc:
            print(exc)


def list(probes):
    """List the sections and subsections and the probe descriptions"""
    for section in probes["cis"]:
        print(f"{section['section_name']} -- {section['description']}")
        for probe in section["probes"]:
            print(f"  {probe['subsection_name']} -- {probe['description']}")


def run_probe(probe):
    """Run the probe and return the result"""
    try:
        result = subprocess.run(
            probe["command"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
        )
        logger.info(f"result.stdout: {result.stdout}")
        logger.info(f"result.stderr: {result.stderr}")
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running probe command with function `run_probe()`: {e}")
        return e


def add_to_report(this_section, probe, analysis):
    """Build the dict with the probe report"""

    # Increment the total_probes and total_passed counters
    report["metadata"]["total_probes"] += 1
    if analysis["result"]:
        report["metadata"]["total_passed"] += 1

    if this_section not in report:
        report[this_section] = {}

    report[this_section][probe["subsection_name"]] = {
        "description": probe["description"],
        "result": analysis["result"],
    }


def analyze_result_of_probe(result, probe):
    """Analyze the result of the probe"""
    analysis = {
        "description": probe["description"],
        "result": "",
    }

    # Begin with known expected conditions conditionals starting with logic flips
    if probe["expected"].startswith("--"):

        # Negative grep condition, if not found then the test passed
        if probe["expected"] == "--grep-negative":
            if not result.stdout and not result.stderr:
                analysis["result"] = True
                return analysis
            else:
                analysis["result"] = False
                return analysis
        else:
            logger.error(
                "Unknown 'expected' condition found in `analyze_results_of_probe()`, defaulting to failed."
            )
            logger.info(
                "Unknown Condition: Add another conditional to handle this `expected` value."
            )
            logger.error(f"Probe: {probe}")
            logger.error(f"result.stdout: {result.stdout}")
            logger.error(f"result.stderr: {result.stderr}")
            report["metadata"]["total_errors"] += 1
            analysis["result"] = False
            return analysis

    # Assume the expected condition is a leading stdout or stderr string
    elif probe["expected"]:
        if result.stdout.decode("utf-8").startswith(
            probe["expected"]
        ) or result.stderr.decode("utf-8").startswith(probe["expected"]):
            analysis["result"] = True
            return analysis
        else:
            analysis["result"] = False
            return analysis

    # Handle some common output states and default results
    else:
        if result.stderr:
            analysis["result"] = False
            return analysis
        elif result.stdout.decode("utf-8").startswith("usage") or result.stdout.decode(
            "utf-8"
        ).startswith("Usage"):
            analysis["result"] = False
            return analysis
        elif result.stdout.decode("utf-8").startswith("error"):
            analysis["result"] = False
            return analysis
        elif result.stdout.decode("utf-8").startswith("not found"):
            analysis["result"] = False
            return analysis
        elif not result.stdout.decode("utf-8"):
            analysis["result"] = False
            return analysis
        elif result.stdout.decode("utf-8"):
            analysis["result"] = True
            return analysis
        else:
            logger.error(
                f"CATCHALL: Unknown result state in `analyze_results_of_probe()`. Defaulting to False."
            )
            logger.error(f"Probe: {probe}")
            logger.error(f"result.stdout: {result.stdout}")
            logger.error(f"result.stderr: {result.stderr}")
            report["metadata"]["total_errors"] += 1
            analysis["result"] = False
            return analysis


@click.command()
@click.option("--yaml_file", default="probes.yaml", help="YAML file to read")
@click.option("--full_output", help="Full CLI output of the probes", is_flag=True)
@click.option("--quiet", "-q", help="Quiet mode only writes to the file", is_flag=True)
@click.option("--output_file", help="Output file to write")
@click.option(
    "--remote_audit_storage",
    default="audit_report.json",  # Default to local storage
    help="Remote audit storage location (S3)",
)
@click.option(
    "--output_file",
    default="audit_report.json",  # Default to local storage
    help="Filename to write the audit report to",
)
@click.option(
    "--ssh_remote_location", help="Remote location to run the probes using SSH."
)
@click.option(
    "--ssm_remote_location", help="Remote location to run the probes using AWS SSM."
)
@click.option("--list_probes", "-l", help="List all probes", is_flag=True)
@click.option("--hardening_level", "-hl", default=1, help="Hardening level to apply")
@click.option("--debug", "-d", help="Debug mode", is_flag=True)
def main(
    yaml_file,
    full_output,
    quiet,
    output_file,
    remote_audit_storage,
    ssh_remote_location,
    ssm_remote_location,
    list_probes,
    hardening_level,
    debug,
):
    """
    A CIS OS benchmarking app, with flexible configuration and output options.

    Results are `true` if the test passed, and `false` if the test failed.
    """

    # BEGIN: Interpret the command line options
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    report["metadata"]["hardening_level"] = hardening_level
    report["metadata"]["remote_log_storage"] = remote_audit_storage
    report["metadata"]["output_file"] = output_file
    report["metadata"]["yaml_file"] = yaml_file

    probes = read_yaml_file(yaml_file)

    # Throw a warning if you are running the wrong YAML locally
    if (
        probes["metadata"]["system"] != platform.system()
        and not ssh_remote_location
        and not ssm_remote_location
    ):
        logger.warning(
            f"YAML file is for {probes['targeting']['system']} but local system is {platform.system()}"
        )

    if list_probes:
        list(probes)
        return
    else:
        # Default to running the probes and writing the report
        report["metadata"]["audited_system"] = platform.platform()
        for section in probes["probes"]:
            this_section = f"{section['section_name']} - {section['description']}"
            for probe in section["probes"]:
                if hardening_level >= probe["level"]:
                    result = run_probe(probe)
                    analysis = analyze_result_of_probe(result, probe)
                    if this_section and probe and analysis:
                        add_to_report(this_section, probe, analysis)
                    else:
                        logger.error(
                            f"Error adding to report.  This section: {this_section}, probe: {probe}, analysis: {analysis}"
                        )
                else:
                    report["metadata"]["total_skipped_probes"] += 1
        # Write the report to a file
        if output_file:
            try:
                with open(output_file, "w") as file:
                    file.write(json.dumps(report, indent=2))
            except Exception as e:
                logger.error(f"Error writing to output file: {e}")
    if full_output and not quiet:
        print(json.dumps(report, indent=2))
    elif not quiet:
        print(json.dumps(report["metadata"], indent=2))

    # END: Interpret the command line options


if __name__ == "__main__":
    main()
