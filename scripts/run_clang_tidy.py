#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run clang-tidy across a curated list of translation units."""

import argparse
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description="Run clang-tidy across one or more translation units")
    parser.add_argument("--clang-tidy", default="clang-tidy", help="clang-tidy executable to run")
    parser.add_argument("--source", action="append", default=[], help="Translation unit to analyze")
    parser.add_argument("compile_args", nargs=argparse.REMAINDER, help="Arguments passed after -- to clang-tidy")
    args = parser.parse_args()

    if not args.source:
        parser.error("at least one --source is required")

    if shutil.which(args.clang_tidy) is None:
        print("clang-tidy executable not found: {}".format(args.clang_tidy), file=sys.stderr)
        return 1

    compile_args = list(args.compile_args)
    if compile_args and compile_args[0] == "--":
        compile_args = compile_args[1:]

    failures = []
    for source in args.source:
        command = [args.clang_tidy, source, "--", *compile_args]
        print("$ {}".format(" ".join(command)))
        result = subprocess.run(command, check=False)
        if result.returncode != 0:
            failures.append((source, result.returncode))

    if failures:
        print("clang-tidy failed for {} translation unit(s)".format(len(failures)), file=sys.stderr)
        for source, returncode in failures:
            print("  {} (exit {})".format(source, returncode), file=sys.stderr)
        return 1

    print("clang-tidy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
