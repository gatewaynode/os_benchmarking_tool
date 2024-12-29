"""
A CIS OS benchmarking app, with flexible configuration and output options.

Results are `true` if the test passed, and `false` if the test failed.
"""

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
logging.basicConfig(level=logging.INFO)

# Probe report global variable
report = {
    "metadata": {
        "description": "CIS OS benchmarking report",
        "date": "{:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.now()),
        "user": os.getlogin(),
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
    """Build the dic with the probe report"""

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
    if probe["expected"] == "grep-negative":
        logger.info(f"In EXPECTED condition: probe['expected']: {probe['expected']}")
        logger.info(f"result.stdout: {result.stdout}")
        logger.info(f"result.stderr: {result.stderr}")
        # Negative grep condition, if not found then the test passed
        if not result.stdout and not result.stderr:
            analysis["result"] = True
            return analysis
        else:
            analysis["result"] = False
            return analysis
    elif probe["expected"]:
        # This only tests if the expected condition for the beginning of the
        # string is known.  This may not be enough.
        if result.stdout.decode("utf-8").startswith(
            probe["expected"]
        ) or result.stderr.decode("utf-8").startswith(probe["expected"]):
            analysis["result"] = True
            return analysis
        else:
            analysis["result"] = False
            return analysis
    else:
        # Common output states and default results
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


@click.command()
@click.option("--yaml_file", default="probes.yaml", help="YAML file to read")
@click.option("--output_file", help="Output file to write")
@click.option("--remote_log_storage", help="Remote log storage location (S3)")
@click.option("--list_probes", "-l", help="List all probes", is_flag=True)
@click.option("--hardening_level", "-hl", default=0, help="Hardening level to apply")
def main(yaml_file, output_file, remote_log_storage, list_probes, hardening_level):
    """
    A CIS OS benchmarking app, with flexible configuration and output options.

    Results are `true` if the test passed, and `false` if the test failed.
    """
    report["metadata"]["hardening_level"] = hardening_level
    report["metadata"]["remote_log_storage"] = remote_log_storage
    report["metadata"]["output_file"] = output_file
    report["metadata"]["yaml_file"] = yaml_file
    probes = read_yaml_file(yaml_file)
    if list_probes:
        list(probes)
        return
    else:
        for section in probes["cis"]:
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
                    print(
                        f"  {probe['subsection_name']} {probe['description']} -- {analysis['result']}"
                    )
    print(json.dumps(report, indent=2))
