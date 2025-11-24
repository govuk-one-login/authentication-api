#!/usr/bin/env python3
"""
Compare Lambda functions between old and new AWS accounts to verify migration.
"""

import boto3
import argparse
import json
import sys
from typing import Dict, List, Any
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_lambda_client(profile: str, region: str):
    """Get Lambda client for specified profile and region."""
    try:
        session = boto3.Session(profile_name=profile)
        client = session.client("lambda", region_name=region)
        # Test the client with a simple call
        client.list_functions(MaxItems=1)
        return client
    except Exception as e:
        if "Token has expired" in str(e) or "sso" in str(e).lower():
            print(f"SSO token expired for profile {profile}.")
            print(f"Please run: aws sso login --profile {profile}")
            sys.exit(1)
        else:
            raise e


def get_iam_client(profile: str, region: str):
    """Get IAM client for specified profile and region."""
    try:
        session = boto3.Session(profile_name=profile)
        client = session.client("iam", region_name=region)
        # Test the client with a simple call
        client.list_roles(MaxItems=1)
        return client
    except Exception as e:
        if "Token has expired" in str(e) or "sso" in str(e).lower():
            print(f"SSO token expired for profile {profile}.")
            print(f"Please run: aws sso login --profile {profile}")
            sys.exit(1)
        else:
            raise e


def get_function_details(lambda_client, func_name: str) -> Dict:
    """Get detailed configuration for a single Lambda function."""
    try:
        config = lambda_client.get_function(FunctionName=func_name)
        func_config = config["Configuration"]

        return {
            "name": func_name,
            "config": func_config,
            "env_vars": func_config.get("Environment", {}).get("Variables", {}),
            "role_arn": func_config["Role"],
        }
    except Exception as e:
        print(f"Error getting details for {func_name}: {e}")
        return None


def list_lambdas(lambda_client, max_workers: int = 10) -> Dict[str, Dict]:
    """List all Lambda functions and their configurations in parallel."""
    # First, get list of all function names
    function_names = []
    paginator = lambda_client.get_paginator("list_functions")

    for page in paginator.paginate():
        for func in page["Functions"]:
            function_names.append(func["FunctionName"])

    print(f"  Found {len(function_names)} functions, fetching details...")

    # Fetch details in parallel
    functions = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_name = {
            executor.submit(get_function_details, lambda_client, name): name
            for name in function_names
        }

        # Collect results
        for future in as_completed(future_to_name):
            result = future.result()
            if result:
                functions[result["name"]] = {
                    "config": result["config"],
                    "env_vars": result["env_vars"],
                    "role_arn": result["role_arn"],
                }

    return functions


def get_role_policies(iam_client, role_arn: str) -> Dict[str, List[str]]:
    """Get all policies attached to a role."""
    role_name = role_arn.split("/")[-1]

    try:
        # Get attached managed policies
        managed_policies = []
        paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            for policy in page["AttachedPolicies"]:
                managed_policies.append(policy["PolicyArn"])

        # Get inline policies
        inline_policies = []
        paginator = iam_client.get_paginator("list_role_policies")
        for page in paginator.paginate(RoleName=role_name):
            inline_policies.extend(page["PolicyNames"])

        return {"managed": managed_policies, "inline": inline_policies}
    except Exception as e:
        print(f"Error getting policies for role {role_name}: {e}")
        return {"managed": [], "inline": []}


def extract_middle_name(full_name: str, filter_string: str) -> str:
    """Extract the middle part of function name for matching."""
    # Remove filter string and common parts
    name = full_name.lower()

    # Remove environment prefix
    prefixes = ["dev-", "authdev1-", "authdev2-", "authdev3-"]
    for prefix in prefixes:
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break

    # Remove filter string if present
    if filter_string.lower() in name:
        name = name.replace(filter_string.lower(), "").strip("-")

    # Remove common suffixes
    suffixes = ["-lambda", "-function"]
    for suffix in suffixes:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break

    return name


def find_matching_functions_with_filter(
    old_functions: Dict, new_functions: Dict, filter_string: str
) -> Dict[str, List[str]]:
    """Find matching functions using filter to identify new functions and extract core names."""
    matches = defaultdict(list)

    # Filter new functions by filter string
    filtered_new = {
        name: func
        for name, func in new_functions.items()
        if filter_string.lower() in name.lower()
    }

    print(f"  Found {len(filtered_new)} functions matching filter '{filter_string}'")

    # For each filtered new function, extract middle name and find matches in old account
    for new_name in filtered_new.keys():
        middle_name = extract_middle_name(new_name, filter_string)

        # Find old functions that contain this middle name
        for old_name in old_functions.keys():
            if middle_name in old_name.lower() and len(middle_name) > 3:
                matches[new_name].append(old_name)
                print(f"  Matched: {old_name} -> {new_name} (via '{middle_name}')")

    return dict(matches)


def compare_env_vars(old_env: Dict, new_env: Dict) -> Dict[str, Any]:
    """Compare environment variables between functions."""
    differences = {"missing_in_new": [], "missing_in_old": [], "different_values": []}

    for key, value in old_env.items():
        if key not in new_env:
            differences["missing_in_new"].append(key)
        elif new_env[key] != value:
            differences["different_values"].append(
                {"key": key, "old_value": value, "new_value": new_env[key]}
            )

    for key in new_env.keys():
        if key not in old_env:
            differences["missing_in_old"].append(key)

    return differences


def compare_function_config(old_config: Dict, new_config: Dict) -> Dict[str, Any]:
    """Compare Lambda function configurations."""
    important_fields = [
        "Runtime",
        "Handler",
        "MemorySize",
        "Timeout",
        "ReservedConcurrencyLimit",
        "DeadLetterConfig",
    ]

    differences = {}

    for field in important_fields:
        old_val = old_config.get(field)
        new_val = new_config.get(field)

        if old_val != new_val:
            differences[field] = {"old": old_val, "new": new_val}

    return differences


def main():
    parser = argparse.ArgumentParser(
        description="Compare Lambda functions between AWS accounts"
    )
    parser.add_argument("--old-account", required=True, help="Old AWS account ID")
    parser.add_argument("--new-account", required=True, help="New AWS account ID")
    parser.add_argument(
        "--old-profile", required=True, help="AWS profile for old account"
    )
    parser.add_argument(
        "--new-profile", required=True, help="AWS profile for new account"
    )
    parser.add_argument(
        "--old-region", default="eu-west-2", help="Region for old account"
    )
    parser.add_argument(
        "--new-region", default="eu-west-2", help="Region for new account"
    )
    parser.add_argument(
        "--filter",
        help='Filter string for new account functions (e.g., "account-management")',
    )
    parser.add_argument("--output", help="Output file for results (JSON)")

    args = parser.parse_args()

    # Initialize clients
    old_lambda = get_lambda_client(args.old_profile, args.old_region)
    new_lambda = get_lambda_client(args.new_profile, args.new_region)
    old_iam = get_iam_client(args.old_profile, args.old_region)
    new_iam = get_iam_client(args.new_profile, args.new_region)

    print(f"Fetching Lambda functions from old account ({args.old_account})...")

    # Fetch from both accounts in parallel
    with ThreadPoolExecutor(max_workers=2) as executor:
        old_future = executor.submit(list_lambdas, old_lambda)
        new_future = executor.submit(list_lambdas, new_lambda)

        old_functions = old_future.result()
        new_functions = new_future.result()

    print(f"Found {len(old_functions)} functions in old account")
    print(f"Found {len(new_functions)} functions in new account")

    # Find matching functions
    if args.filter:
        print(f"Using filter: '{args.filter}'")
        matches = find_matching_functions_with_filter(
            old_functions, new_functions, args.filter
        )
    else:
        print("No filter specified - comparing all functions")
        matches = find_matching_functions_with_filter(old_functions, new_functions, "")

    results = {
        "summary": {
            "old_account_functions": len(old_functions),
            "new_account_functions": len(new_functions),
            "matched_functions": len(matches),
            "unmatched_old_functions": [],
        },
        "comparisons": [],
    }

    # Compare matched functions
    for new_name, old_names in matches.items():
        new_func = new_functions[new_name]

        for old_name in old_names:
            old_func = old_functions[old_name]

            print(f"\nComparing {old_name} -> {new_name}")

            # Compare configurations
            config_diff = compare_function_config(
                old_func["config"], new_func["config"]
            )

            # Compare environment variables
            env_diff = compare_env_vars(old_func["env_vars"], new_func["env_vars"])

            # Get role policies
            old_policies = get_role_policies(old_iam, old_func["role_arn"])
            new_policies = get_role_policies(new_iam, new_func["role_arn"])

            comparison = {
                "old_function": old_name,
                "new_function": new_name,
                "config_differences": config_diff,
                "env_var_differences": env_diff,
                "old_role_policies": old_policies,
                "new_role_policies": new_policies,
                "status": "PASS"
                if not config_diff and not any(env_diff.values())
                else "REVIEW",
            }

            results["comparisons"].append(comparison)

            # Print summary
            if comparison["status"] == "PASS":
                print("  ✅ PASS - No significant differences")
            else:
                print("  ⚠️  REVIEW - Differences found:")

                # Show config differences
                if config_diff:
                    print("    📋 Config differences:")
                    for field, values in config_diff.items():
                        print(f"      {field}: {values['old']} -> {values['new']}")

                # Show env var differences
                if env_diff["missing_in_new"]:
                    print(
                        f"    🔴 Missing env vars in new: {env_diff['missing_in_new']}"
                    )
                if env_diff["missing_in_old"]:
                    print(f"    🟡 New env vars: {env_diff['missing_in_old']}")
                if env_diff["different_values"]:
                    print("    🔄 Changed env vars:")
                    for diff in env_diff["different_values"]:
                        print(
                            f"      {diff['key']}: '{diff['old_value']}' -> '{diff['new_value']}'"
                        )

                # Show policy differences with names
                old_managed = set(old_policies["managed"])
                new_managed = set(new_policies["managed"])

                if old_managed != new_managed:
                    print(
                        f"    🔐 Managed policies: {len(old_managed)} -> {len(new_managed)}"
                    )

                    missing_in_new = old_managed - new_managed
                    if missing_in_new:
                        print(f"      🔴 Missing in new: {sorted(missing_in_new)}")

                    new_additions = new_managed - old_managed
                    if new_additions:
                        print(f"      🟢 New additions: {sorted(new_additions)}")

                old_inline = set(old_policies["inline"])
                new_inline = set(new_policies["inline"])

                if old_inline != new_inline:
                    print(
                        f"    📝 Inline policies: {len(old_inline)} -> {len(new_inline)}"
                    )

                    missing_inline = old_inline - new_inline
                    if missing_inline:
                        print(f"      🔴 Missing inline: {sorted(missing_inline)}")

                    new_inline_additions = new_inline - old_inline
                    if new_inline_additions:
                        print(f"      🟢 New inline: {sorted(new_inline_additions)}")

    # Find unmatched functions
    matched_old_names = set()
    for old_names in matches.values():
        matched_old_names.update(old_names)

    unmatched = [name for name in old_functions.keys() if name not in matched_old_names]
    results["summary"]["unmatched_old_functions"] = unmatched

    if unmatched:
        print(f"\n❌ Unmatched functions in old account: {len(unmatched)}")
        for name in unmatched:
            print(f"  - {name}")

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")

    # Summary
    total_comparisons = len(results["comparisons"])
    passed = sum(1 for c in results["comparisons"] if c["status"] == "PASS")

    print("\n📊 Summary:")
    print(f"  Total comparisons: {total_comparisons}")
    print(f"  Passed: {passed}")
    print(f"  Need review: {total_comparisons - passed}")
    print(f"  Unmatched: {len(unmatched)}")


if __name__ == "__main__":
    main()
