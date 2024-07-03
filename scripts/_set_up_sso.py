#!/usr/bin/env python3
import configparser
import json
import logging
import os
import re
import shutil
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from time import sleep

if os.getenv("FROM_WRAPPER", "false") != "true":
    print(
        "This script is intended to be run from the wrapper `scripts/set-up-sso.sh`. "
        "Please use that instead."
    )
    sys.exit(1)

try:
    import boto3
    from botocore.config import Config
except ImportError:
    print(
        "boto3 is not installed. Please refer to "
        "https://govukverify.atlassian.net/wiki/x/IgFm5 for instructions."
    )
    sys.exit(1)


StrAnyDict = dict[str, object()]

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("set-up-sso")

INCLUDE_PROD = os.getenv("INCLUDE_PROD", "false") == "YES I AM SURE"
if INCLUDE_PROD:
    logger.warning(
        "You have enabled production account profiles. This is not recommended"
        " unless you are about to perform a production operation."
    )
    logger.warning(
        "Run again without setting `INCLUDE_PROD` environment variable once you are"
        " done."
    )

# Global constants
AWS_CONFIG_DIR: Path = Path.home() / ".aws"
AWS_CONFIG_FILE: Path = AWS_CONFIG_DIR / "config"
AWS_CONFIG_BACKUP_DIR: Path = AWS_CONFIG_DIR / "auth-set-up-sso-backups"

DEFAULT_REGION = "eu-west-2"
SESSION_NAME = "di-sso"
SESSION_START_URL = "https://uk-digital-identity.awsapps.com/start"
SESSION_REGISTRATION_SCOPES = "sso:account:access"

oidc_client_cache: Path = (
    Path.home() / ".aws" / "sso" / "cache" / "di-auth_set-up-sso.json"
)


def backup_existing_config(retain_count: int = 20):
    AWS_CONFIG_BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    backup_file = AWS_CONFIG_BACKUP_DIR / f"config.backup.{datetime.now().isoformat()}"
    logger.info("Backing up existing AWS config to %s", backup_file)
    shutil.copy2(AWS_CONFIG_FILE, backup_file)

    # Get the number of existing backups, sorted by date (oldest -> newest)
    existing_backups = sorted(AWS_CONFIG_BACKUP_DIR.glob("config.backup.*"))

    deleted_backups = 0
    while len(existing_backups) > retain_count:
        # Delete oldest backup
        oldest_backup = existing_backups.pop(0)
        oldest_backup.unlink()
        logger.debug("Deleted old backup %s", oldest_backup)
        deleted_backups += 1

    if deleted_backups > 0:
        logger.info(
            "Deleted %d old backup%s",
            deleted_backups,
            "s" if deleted_backups > 1 else "",
        )


def setup_aws_config():
    # Check if AWS config directory exists, if not, create it
    AWS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    # Backup existing config file
    if AWS_CONFIG_FILE.exists():
        backup_existing_config()

    # Load AWS config file
    config = configparser.ConfigParser()
    config.read(AWS_CONFIG_FILE)

    sso_session_section_title = f"sso-session {SESSION_NAME}"

    # Remove existing SSO session
    if sso_session_section_title in config:
        del config[sso_session_section_title]

    # Add new SSO session
    config[sso_session_section_title] = {
        "sso_start_url": SESSION_START_URL,
        "sso_region": DEFAULT_REGION,
        "sso_registration_scopes": SESSION_REGISTRATION_SCOPES,
    }

    # Write config file
    with AWS_CONFIG_FILE.open("w", encoding="utf-8") as f:
        config.write(f)


def login_to_sso() -> StrAnyDict:
    sso_session = boto3.Session()
    sso_client = sso_session.client(
        "sso-oidc",
        region_name=DEFAULT_REGION,
        aws_access_key_id="",
        aws_secret_access_key="",
    )

    # Load or register SSO OIDC client
    try:
        oidc_client_cache.parent.mkdir(parents=True, exist_ok=True)
        client_creds = json.loads(oidc_client_cache.read_text())
        assert (
            client_creds["clientSecretExpiresAt"] > datetime.now().timestamp()
        ), "Client has expired."
    except (FileNotFoundError, json.JSONDecodeError, AssertionError, KeyError) as e:
        logger.debug("Error loading cached client: %s", e)
        logger.debug("Registering new client.")
        client_creds = sso_client.register_client(
            clientName="set-up-sso.py",
            clientType="public",
            scopes=["sso:account:access"],
        )
        del client_creds["ResponseMetadata"]
        oidc_client_cache.write_text(json.dumps(client_creds))

    device_auth = sso_client.start_device_authorization(
        clientId=client_creds["clientId"],
        clientSecret=client_creds["clientSecret"],
        startUrl=SESSION_START_URL,
    )

    try:
        webbrowser.open(device_auth["verificationUriComplete"], autoraise=True)
    except webbrowser.Error:
        pass

    print(
        "Please grant access to the application. Your browser should open "
        f"automatically, with the user code '{device_auth['userCode']}'."
    )
    print(
        "If it does not, please approve at the following URL: ",
        device_auth["verificationUriComplete"],
        "\n",
    )

    for _ in range(1, device_auth["expiresIn"] // device_auth["interval"] + 1):
        try:
            return sso_client.create_token(
                clientId=client_creds["clientId"],
                clientSecret=client_creds["clientSecret"],
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=device_auth["deviceCode"],
            )
        except sso_client.exceptions.AuthorizationPendingException:
            pass
        sleep(device_auth["interval"])

    print("Device code expired. Please try again.")
    sys.exit(1)


def get_aws_accounts_and_roles(sso_token: StrAnyDict) -> list[StrAnyDict]:
    # Get AWS accounts and roles
    client_config = Config(retries={"max_attempts": 10, "mode": "adaptive"})
    client = boto3.client("sso", region_name=DEFAULT_REGION, config=client_config)

    paginator = client.get_paginator("list_accounts")
    iterator = paginator.paginate(accessToken=sso_token["accessToken"])
    accounts = []
    for page in iterator:
        accounts.extend(page["accountList"])

    for _, account in enumerate(accounts):
        paginator = client.get_paginator("list_account_roles")
        iterator = paginator.paginate(
            accessToken=sso_token["accessToken"], accountId=account["accountId"]
        )
        account["roleList"] = []
        for page in iterator:
            account["roleList"].extend(page["roleList"])

        account["roles"] = [role["roleName"] for role in account["roleList"]]
    return accounts


def account_is_prod(account: StrAnyDict) -> bool:
    """
    Checks if the given AWS account is a production account.

    This function checks if the name of the account contains the word "prod" or
    "production", ignoring case. The word must be a whole word, i.e. "nonprod"
    will not match.

    Args:
        account (StrAnyDict): A dictionary representing an AWS account. The dictionary
            must contain a key "accountName" with a string value representing the name
            of the account.

    Returns:
        bool: True if the account is a production account, False otherwise.
    """
    return (
        re.search(r"\bprod(?:uction)?\b", account["accountName"], re.IGNORECASE)
        is not None
    )


def role_ends_with(role_name: str, test_string: str) -> bool:
    """
    Checks if the given AWS role contains a specific string.

    This function checks if the name of the role contains a specific string, ignoring
    case. The string must be a whole word, i.e. "admin" will not match "administrator".

    Args:
        role (StrAnyDict): A dictionary representing an AWS role. The dictionary must
            contain a key "roleName" with a string value representing the name of the
            role.
        test_string (str): The string to test for.

    Returns:
        bool: True if the role contains the string, False otherwise.
    """
    return re.search(rf"\b{test_string}$", role_name, re.IGNORECASE) is not None


def role_is_admin(role_name: str) -> bool:
    return (
        role_ends_with(role_name, "admin")
        or role_ends_with(role_name, "administrator")
        or role_ends_with(role_name, "AWSAdministratorAccess")
    )


def role_is_readonly(role_name: str) -> bool:
    return (
        role_ends_with(role_name, "readonly")
        or role_ends_with(role_name, "read-only")
        or role_ends_with(role_name, "ReadOnlyAccess")
    )


def account_has_named_role(account: StrAnyDict, role_name: str) -> bool:
    return any(role["roleName"] == role_name for role in account["roleList"])


def create_aws_profiles(accounts: list[StrAnyDict]):
    # Create AWS profiles
    config = configparser.ConfigParser()
    config.read(AWS_CONFIG_FILE)

    for account in accounts:
        account["profiles"] = {}
        account_name = account["accountName"]

        if "AWSAdministratorAccess" in account["roles"]:
            account["profiles"][f"{account_name}-admin"] = {
                "name": f"{account_name}-admin",
                "roleName": "AWSAdministratorAccess",
            }
            account["roles"].remove("AWSAdministratorAccess")

        if "ReadOnlyAccess" in account["roles"]:
            account["profiles"][f"{account_name}-readonly"] = {
                "name": f"{account_name}-readonly",
                "roleName": "ReadOnlyAccess",
            }
            account["roles"].remove("ReadOnlyAccess")

        for role in account["roles"]:
            profile_name = None

            if role_is_admin(role):
                profile_name = f"{account_name}-admin"
                if profile_name in account["profiles"].keys():
                    continue
            elif role_is_readonly(role):
                profile_name = f"{account_name}-readonly"
                if profile_name in account["profiles"].keys():
                    continue

            if profile_name is None:
                logger.warning(
                    "Role name %s does not match any known patterns or is"
                    " already in use. Using %s-%s instead.",
                    role,
                    account_name,
                    role,
                )
                profile_name = f"{account_name}-{role}"

            account["profiles"][profile_name] = {
                "name": profile_name,
                "roleName": role,
            }

        for profile_name, profile in account["profiles"].items():
            profile_section_title = f"profile {profile_name}"
            if (
                account_is_prod(account)
                and not INCLUDE_PROD
                and not role_is_readonly(profile_name)
            ):
                if profile_section_title in config:
                    config.remove_section(profile_section_title)
                    logger.warning(
                        "Removed profile %s as it is a production account.",
                        profile_name,
                    )
                else:
                    logger.warning(
                        "Not adding profile %s as it is a production account.",
                        profile_name,
                    )
                continue
            if profile_section_title in config:
                logger.info(
                    "Updating profile %s: %s:%s",
                    profile_name,
                    account["accountId"],
                    profile["roleName"],
                )
                config.remove_section(profile_section_title)
            else:
                logger.info(
                    "Adding profile %s: %s:%s",
                    profile_name,
                    account["accountId"],
                    profile["roleName"],
                )

            config[profile_section_title] = {
                "sso_session": SESSION_NAME,
                "sso_account_id": account["accountId"],
                "sso_role_name": profile["roleName"],
                "sso_region": DEFAULT_REGION,
                "sso_start_url": SESSION_START_URL,
                "region": DEFAULT_REGION,
            }

    # Write config file
    with AWS_CONFIG_FILE.open("w", encoding="utf-8") as f:
        config.write(f)


def main():
    setup_aws_config()
    token = login_to_sso()
    accounts = get_aws_accounts_and_roles(token)
    create_aws_profiles(accounts)


if __name__ == "__main__":
    main()
