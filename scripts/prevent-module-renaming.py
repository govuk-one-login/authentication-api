#!/usr/bin/env python3
import argparse
import os
import sys

import hcl2
from git import Repo

FROM_REF = os.getenv("PRE_COMMIT_FROM_REF", "HEAD")
TO_REF = os.getenv("PRE_COMMIT_TO_REF", None)


def get_removed_modules(called_manually: bool = True) -> dict[str, str]:
    repo = Repo(os.getcwd())
    if called_manually:
        try:
            merge_base = repo.merge_base(repo.head.commit, "main")[0]
            diffs = merge_base.diff(None)
            diffs += repo.head.commit.diff(None)
        except Exception:
            diffs = repo.index.diff(None)
            diffs += repo.head.commit.diff(None)
    else:
        diffs = repo.commit(FROM_REF).diff(TO_REF)

    modules_and_origin: dict[str, str] = {}
    before = set()
    after = set()
    for diff in diffs:
        if not diff.a_path.endswith(".tf"):
            continue
        if diff.change_type not in ["M", "D"]:
            continue
        before_modules = extract_module_names(
            hcl2.loads(diff.a_blob.data_stream.read().decode())
        )
        for module_name in before_modules:
            modules_and_origin[module_name] = diff.a_path
        before.update(before_modules)
        try:
            after.update(
                extract_module_names(
                    hcl2.loads(diff.b_blob.data_stream.read().decode())
                )
            )
        except AttributeError:
            pass

    return {module: modules_and_origin[module] for module in before - after}


def extract_module_names(hcldict: dict) -> set[str]:
    modules = hcldict.get("module", [])
    module_names = set()
    for module in modules:
        for module_name, config in module.items():
            if "endpoint-module-v2" in config.get("source", ""):
                module_names.add(module_name)
    return module_names


if __name__ == "__main__":
    if os.getenv("PRE_COMMIT", "0") == "0":
        print("This script is meant to be run by pre-commit.", file=sys.stderr)
        sys.exit(1)
    parser = argparse.ArgumentParser()
    parser.add_argument("--manual", action="store_true", default=False)
    args = parser.parse_args()

    removed_modules = get_removed_modules(args.manual)

    if removed_modules:
        print(
            "The following 'endpoint-module-v2' terraform modules were removed (or renamed). This causes problems and should not be done.",
            file=sys.stderr,
        )
        for module_name, original_path in removed_modules.items():
            print(f"{module_name} ({original_path})", file=sys.stderr)
        sys.exit(1)
    else:
        print("No modules were removed.", file=sys.stderr)
