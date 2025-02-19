#!/usr/bin/env python3

import argparse
import json
import multiprocessing
import os
import pathlib
import subprocess
import sys
from collections import defaultdict
from functools import cache
from multiprocessing.pool import AsyncResult

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(REPO_ROOT, ".tflint.hcl")


def run_tflint(
    directory: pathlib.Path, files: list[str], args: list[str]
) -> subprocess.Popen:
    # strip out the format argument, as we are always going to use 'json'
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--format")
    parsed, unknown = parser.parse_known_args(args)

    filter_args = [f"--filter={file}" for file in files]

    cmd = (
        [
            "tflint",
            "--config",
            CONFIG_FILE,
            "--chdir",
            str(directory),
            "--format",
            "json",
        ]
        + filter_args
        + unknown
    )
    return subprocess.run(cmd, capture_output=True)


class TflintResult:
    def __init__(self, result: subprocess.CompletedProcess):
        self.result = result

    @cache
    def _data(self):
        return json.loads(self.result.stdout)

    def issues(self):
        for issue in self._data()["issues"]:
            yield issue

    def errors(self):
        for error in self._data()["errors"]:
            yield error

    @property
    def return_code(self):
        return self.result.returncode

    @property
    def error(self):
        return any([error for error in self.errors()])


class TflintResults:
    results: list[TflintResult] = []

    def __init__(self, results: list[subprocess.CompletedProcess]):
        self.results = [TflintResult(result) for result in results]

    @property
    def was_error(self):
        return any([result.error for result in self.results])

    def issues(self):
        for result in self.results:
            yield from result.issues()

    def errors(self):
        for result in self.results:
            yield from result.errors()

    @property
    def return_code(self):
        return max([result.return_code for result in self.results])


def parse_tflint_runs(runs: list[subprocess.CompletedProcess]) -> list[TflintResult]:
    pass


def main(args: argparse.Namespace, tflint_args: list[str]):
    directories = defaultdict(list[str])
    file: pathlib.Path
    for file in args.files:
        parent = file.parent
        directories.setdefault(parent, []).append(file.name)

    try:
        subprocess.run(
            ["tflint", "--config", CONFIG_FILE, "--init"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        print(e.stdout)
        sys.exit(e.returncode)

    results: list[subprocess.CompletedProcess] = []
    with multiprocessing.Pool(len(directories.keys())) as pool:
        processes: list[AsyncResult] = []
        for directory, files in directories.items():
            processes.append(
                pool.apply_async(run_tflint, (directory, files, tflint_args))
            )
        while not all([result.ready() for result in processes]):
            pass
        for result in processes:
            results.append(result.get())

    parsed_results = TflintResults(results)
    if parsed_results.was_error:
        for error in parsed_results.errors():
            print(f"Error: {error['message']}")
        sys.exit(parsed_results.return_code)
    issues = list(parsed_results.issues())
    if issues:
        print(f"{len(issues)} issue(s) found:\n")
        for issue in issues:
            rule = issue["rule"]
            range = issue["range"]
            print(
                f"{range['filename']}:{range['start']['line']}:{range['start']['column']}: {rule['severity'].title()} - {issue['message']} ({rule['name']})"
            )
    sys.exit(parsed_results.return_code)


class ValidatePathAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        pvalues = []
        for value in values:
            path = pathlib.Path(value)
            if not path.exists():
                parser.error(f"Path {value} does not exist.")
            if not path.is_file():
                parser.error(f"Path {value} is not a file.")
            pvalues.append(path)
        setattr(namespace, self.dest, pvalues)


if __name__ == "__main__":
    app_parser = argparse.ArgumentParser(
        usage="%(prog)s [tflint-options] FILE [FILE ...]",
    )
    app_parser.add_argument(
        "files",
        nargs="+",
        help="file(s) to lint",
        metavar="FILE",
        action=ValidatePathAction,
    )
    app_args, tflint_args = app_parser.parse_known_args()
    main(app_args, tflint_args)
