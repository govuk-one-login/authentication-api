#!/usr/bin/env python3
import configparser
import json
import logging
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    import boto3
except ImportError:
    print("boto3 is not installed. Please install it using `pip3 install boto3`")
    sys.exit(1)

# Global constants
AWS_CONFIG_DIR: Path = Path.home() / ".aws"
AWS_CONFIG_FILE: Path = AWS_CONFIG_DIR / "config"
DEFAULT_REGION = "eu-west-2"
SESSION_NAME = "di-sso"
SESSION_START_URL = "https://uk-digital-identity.awsapps.com/start"
SESSION_REGISTRATION_SCOPES = "sso:account:access"

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def setup_aws_config():
    # Check if AWS config directory exists, if not, create it
    AWS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    # Backup existing config file
    if AWS_CONFIG_FILE.exists():
        backup_file = AWS_CONFIG_FILE.with_suffix(
            f".backup.{datetime.now().isoformat()}"
        )
        shutil.copy2(AWS_CONFIG_FILE, backup_file)

    # Load AWS config file
    config = configparser.ConfigParser()
    config.read(AWS_CONFIG_FILE)

    SSO_SESSION_SECTION_TITLE = f"sso-session {SESSION_NAME}"

    # Remove existing SSO session
    if SSO_SESSION_SECTION_TITLE in config:
        del config[SSO_SESSION_SECTION_TITLE]

    # Add new SSO session
    config[SSO_SESSION_SECTION_TITLE] = {
        "sso_start_url": SESSION_START_URL,
        "sso_region": DEFAULT_REGION,
        "sso_registration_scopes": SESSION_REGISTRATION_SCOPES,
    }

    # Write config file
    with open(AWS_CONFIG_FILE, "w") as f:
        config.write(f)


def login_to_sso():
    # Login to AWS SSO
    try:
        subprocess.run(["aws", "sso", "login", "--sso-session", SESSION_NAME])
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to log in to SSO: {e}")
        sys.exit(1)


def fetch_sso_credentials():
    # Fetch SSO credentials from cache
    sso_cache_dir = Path.home() / ".aws" / "sso" / "cache"
    sso_caches = list(sso_cache_dir.glob("*.json"))
    sso_caches.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    with open(sso_caches[0]) as f:
        sso_cache = json.load(f)
    return sso_cache


def get_aws_accounts_and_roles(sso_cache):
    # Get AWS accounts and roles
    client = boto3.client("sso", region_name=DEFAULT_REGION)
    paginator = client.get_paginator("list_accounts")
    iterator = paginator.paginate(accessToken=sso_cache["accessToken"])
    accounts = []
    for page in iterator:
        accounts.extend(page["accountList"])

    for i, account in enumerate(accounts):
        paginator = client.get_paginator("list_account_roles")
        iterator = paginator.paginate(
            accessToken=sso_cache["accessToken"], accountId=account["accountId"]
        )
        account["roleList"] = []
        for page in iterator:
            account["roleList"].extend(page["roleList"])
    return accounts


def create_aws_profiles(accounts):
    # Create AWS profiles
    config = configparser.ConfigParser()
    config.read(AWS_CONFIG_FILE)

    created_profiles = []
    for account in accounts:
        account_name = account["accountName"]
        for role in account["roleList"]:
            role_name: str = role["roleName"]
            profile_name = None

            if "-admin" in role_name.lower():
                _name = f"{account_name}-admin"
                if _name not in created_profiles:
                    # Skip if profile already exists, we'll use a generic name later
                    profile_name = _name
            elif any(
                substring in role_name.lower()
                for substring in ["-readonly", "-read-only"]
            ):
                _name = f"{account_name}-readonly"
                if _name not in created_profiles:
                    # Skip if profile already exists, we'll use a generic name later
                    profile_name = _name

            if profile_name is None:
                logging.warning(
                    f"Role name {role_name} does not match any known patterns or is"
                    f" already in use. Using {account_name}-{role_name} instead."
                )
                profile_name = f"{account_name}-{role_name}"

            profile_section_title = f"profile {profile_name}"
            if profile_section_title in config:
                logging.info(
                    f"Updating profile {profile_name}: {account['accountId']}:"
                    f"{role_name}"
                )
                config.remove_section(profile_section_title)
            else:
                logging.info(
                    f"Adding profile {profile_name}: {account['accountId']}:{role_name}"
                )

            config[profile_section_title] = {
                "sso_session": SESSION_NAME,
                "sso_account_id": account["accountId"],
                "sso_role_name": role_name,
                "sso_region": DEFAULT_REGION,
                "sso_start_url": SESSION_START_URL,
                "region": DEFAULT_REGION,
            }
            created_profiles.append(profile_name)

    # Write config file
    with open(AWS_CONFIG_FILE, "w") as f:
        config.write(f)


def main():
    setup_aws_config()
    login_to_sso()
    sso_cache = fetch_sso_credentials()
    accounts = get_aws_accounts_and_roles(sso_cache)
    create_aws_profiles(accounts)


if __name__ == "__main__":
    main()
