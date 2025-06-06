#!/usr/bin/env python3

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable, TypedDict

import boto3

secretsmanager = boto3.client("secretsmanager")


class Secret(TypedDict):
    ARN: str
    Name: str
    VersionId: str
    SecretString: str
    VersionStages: list[str]
    CreatedData: datetime


def read_all_secrets(filter: dict, next_token: str = "") -> Iterable[Secret]:
    """Read all secrets from AWS Secrets Manager."""

    while next_token is not None:
        req_args = {
            "Filters": [filter],
            "NextToken": next_token,
        }
        if next_token == "":
            del req_args["NextToken"]
        res = secretsmanager.batch_get_secret_value(**req_args)
        yield from res.get("SecretValues", [])
        next_token = res.get("NextToken")


def escape_string(string: str) -> str:
    """Escape a string for Terraform."""
    return string.replace('"', '\\"')


try:
    environment_name = secrets_environment_name = sys.argv[1]
except IndexError:
    print("Please provide an environment name as the first argument.")
    sys.exit(1)

print_filename = False
try:
    output_file = Path(sys.argv[2])
except IndexError:
    import tempfile

    output_file = (
        Path(tempfile.gettempdir()) / f"{environment_name}-secrets.tfvars.json"
    )
    print_filename = True

# Unsure why this is needed, but it is.
if environment_name == "dev":
    secrets_environment_name = "build"

prefix = f"/deploy/{secrets_environment_name}/"
secrets = read_all_secrets(
    filter={
        "Key": "name",
        "Values": [
            prefix,
        ],
    }
)
tfvars = {s["Name"].removeprefix(prefix): s["SecretString"] for s in secrets}
output_file.write_text(json.dumps(tfvars, indent=4))
if print_filename:
    print(output_file)
