# Generate tests for the files in ./cis_benchmark_bash_to_python files

import pytest
import os
from click.testing import CliRunner
from cis_benchmark_bash_to_python import main as app

test_filename = "test_something.json"


def test_yaml_file():
    runner = CliRunner()
    result = runner.invoke(
        app.main, ["--yaml_file", "tests/testing_RHEL_8_probes.yaml"]
    )

    assert result.exit_code == 0


def test_full_output():
    runner = CliRunner()
    result = runner.invoke(
        app.main, ["--full_output", "--yaml_file", "tests/testing_RHEL_8_probes.yaml"]
    )

    assert result.exit_code == 0


def test_quiet():
    runner = CliRunner()
    result = runner.invoke(
        app.main, ["--quiet", "--yaml_file", "tests/testing_RHEL_8_probes.yaml"]
    )

    assert result.exit_code == 0


def test_remote_audit_storage():
    runner = CliRunner()
    result = runner.invoke(
        app.main,
        [
            "--remote_audit_storage",
            "some/s3/bucket/url",
            "--yaml_file",
            "tests/testing_RHEL_8_probes.yaml",
        ],
    )

    assert result.exit_code == 0


def test_output_file():
    runner = CliRunner()
    result = runner.invoke(
        app.main,
        [
            "--output_file",
            test_filename,
            "--yaml_file",
            "tests/testing_RHEL_8_probes.yaml",
        ],
    )

    assert result.exit_code == 0
    assert os.path.isfile(test_filename)
    os.remove(test_filename)


def test_ssh_remote_location():
    runner = CliRunner()
    result = runner.invoke(
        app.main,
        [
            "--ssh_remote_location",
            "some/ssh/location",
            "--yaml_file",
            "tests/testing_RHEL_8_probes.yaml",
        ],
    )

    assert result.exit_code == 0


def test_ssm_remote_location():
    runner = CliRunner()
    result = runner.invoke(
        app.main,
        [
            "--ssm_remote_location",
            "some/instance/id",
            "--yaml_file",
            "tests/testing_RHEL_8_probes.yaml",
        ],
    )

    assert result.exit_code == 0


def test_list():
    runner = CliRunner()
    result = runner.invoke(
        app.main, ["--list", "--yaml_file", "tests/testing_RHEL_8_probes.yaml"]
    )

    assert result.exit_code == 0


def test_hardening_level():
    runner = CliRunner()
    result = runner.invoke(
        app.main,
        ["--hardening_level", 3, "--yaml_file", "tests/testing_RHEL_8_probes.yaml"],
    )

    assert result.exit_code == 0


def test_debug():
    runner = CliRunner()
    result = runner.invoke(
        app.main,
        ["--debug", "--yaml_file", "tests/testing_RHEL_8_probes.yaml"],
    )

    assert result.exit_code == 0
