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

try:
    import boto3
except ImportError:
    print("boto3 is not installed. Please install it using `pip3 install boto3`")
    sys.exit(1)

StrAnyDict = dict[str, object()]

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

INCLUDE_PROD = os.getenv("INCLUDE_PROD", "false") == "YES I AM SURE"
if INCLUDE_PROD:
    logging.warning(
        "You have enabled production account profiles. This is not recommended"
        " unless you are about to perform a production operation."
    )
    logging.warning(
        "Run again without setting `INCLUDE_PROD` environment variable once you are"
        " done."
    )

# Global constants
AWS_CONFIG_DIR: Path = Path.home() / ".aws"
AWS_CONFIG_FILE: Path = AWS_CONFIG_DIR / "config"
DEFAULT_REGION = "eu-west-2"
SESSION_NAME = "di-sso"
SESSION_START_URL = "https://uk-digital-identity.awsapps.com/start"
SESSION_REGISTRATION_SCOPES = "sso:account:access"

oidc_client_cache: Path = (
    Path.home() / ".aws" / "sso" / "cache" / "di-auth_set-up-sso.json"
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
        logging.debug(f"Error loading cached client: {e}")
        logging.debug("Registering new client.")
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
    else:
        print("Device code expired. Please try again.")
        sys.exit(1)


def get_aws_accounts_and_roles(sso_token: StrAnyDict) -> list[StrAnyDict]:
    # Get AWS accounts and roles
    client = boto3.client("sso", region_name=DEFAULT_REGION)
    paginator = client.get_paginator("list_accounts")
    iterator = paginator.paginate(accessToken=sso_token["accessToken"])
    accounts = []
    for page in iterator:
        accounts.extend(page["accountList"])

    for i, account in enumerate(accounts):
        paginator = client.get_paginator("list_account_roles")
        iterator = paginator.paginate(
            accessToken=sso_token["accessToken"], accountId=account["accountId"]
        )
        account["roleList"] = []
        for page in iterator:
            account["roleList"].extend(page["roleList"])
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


def role_ends_with(role: StrAnyDict, test_string: str) -> bool:
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
    return re.search(rf"\b{test_string}$", role["roleName"], re.IGNORECASE) is not None


def role_is_admin(role: StrAnyDict) -> bool:
    return role_ends_with(role, "admin") or role_ends_with(role, "administrator")


def role_is_readonly(role: StrAnyDict) -> bool:
    return role_ends_with(role, "readonly") or role_ends_with(role, "read-only")


def create_aws_profiles(accounts: list[StrAnyDict]):
    # Create AWS profiles
    config = configparser.ConfigParser()
    config.read(AWS_CONFIG_FILE)

    created_profiles = []
    for account in accounts:
        account_name = account["accountName"]
        for role in account["roleList"]:
            role_name: str = role["roleName"]
            profile_name = None

            if role_is_admin(role):
                _name = f"{account_name}-admin"
                if _name not in created_profiles:
                    # Skip if profile already exists, we'll use a generic name later
                    profile_name = _name
            elif role_is_readonly(role):
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
            if account_is_prod(account) and not INCLUDE_PROD:
                if profile_section_title in config:
                    config.remove_section(profile_section_title)
                    logging.warning(
                        f"Removed profile {profile_name} as it is a production account."
                    )
                else:
                    logging.warning(
                        f"Not adding profile {profile_name} as it is a production"
                        " account."
                    )
                continue
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
    token = login_to_sso()
    accounts = get_aws_accounts_and_roles(token)
    create_aws_profiles(accounts)


if __name__ == "__main__":
    main()
