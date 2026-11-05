#!/usr/bin/env python3
"""Finite parent-edit/raster source policy; not a general Rust soundness proof."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sys

CAP = 1024 * 1024
RAW_START = re.compile(r'r(#{0,64})"')
CHAR = re.compile(r"'(?:(?:[^'\\\n])|(?:\\(?:['\"\\nrt0]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,12}\})))'")


def code_only(text):
    """Erase Rust comments/string contents for these selected call-token checks."""
    result = list(text)
    index = 0
    while index < len(text):
        end = None
        if text.startswith("//", index):
            end = text.find("\n", index)
            if end < 0:
                end = len(text)
        elif text.startswith("/*", index):
            depth, position = 1, index + 2
            while position < len(text) and depth:
                if text.startswith("/*", position):
                    depth += 1
                    position += 2
                elif text.startswith("*/", position):
                    depth -= 1
                    position += 2
                else:
                    position += 1
                if depth > 64:
                    raise ValueError("source comment depth")
            if depth:
                raise ValueError("unterminated source comment")
            end = position
        elif text[index] == "'" and (character := CHAR.match(text, index)):
            end = character.end()
        elif text[index] == 'r':
            match = RAW_START.match(text, index)
            if match:
                closing = '"' + match[1]
                stop = text.find(closing, match.end())
                if stop < 0:
                    raise ValueError("unterminated raw source string")
                end = stop + len(closing)
        elif text[index] == '"':
            position = index + 1
            while position < len(text):
                if text[position] == '\\':
                    position += 2
                elif text[position] == '"':
                    end = position + 1
                    break
                else:
                    position += 1
            if end is None:
                raise ValueError("unterminated source string")
        if end is not None:
            for offset in range(index, end):
                if result[offset] != '\n':
                    result[offset] = ' '
            index = end
        else:
            index += 1
    return ''.join(result)


def check(raw):
    if not 0 < len(raw) <= CAP:
        raise ValueError("bounded nonempty selected Rust source")
    code = code_only(raw.decode("utf8", "strict"))
    if re.search(r"\b(?:step_native_editor|apply_key)\s*\(", code):
        return "PROCESS_SOURCE_FORBIDDEN_PARENT_EDIT"
    if re.search(r"\b(?:render_native_editor|rasterize_bgra)\s*\(", code):
        return "PROCESS_SOURCE_FORBIDDEN_PARENT_RASTER"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    fd = os.open(args.source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        import stat
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= CAP:
            raise ValueError("bounded regular selected source")
        with os.fdopen(fd, "rb", closefd=False) as source:
            raw = source.read(CAP + 1)
        after = os.fstat(fd)
        stable = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in stable):
            raise ValueError("selected source changed during read")
    finally:
        os.close(fd)
    diagnostic = check(raw)
    if diagnostic:
        print(diagnostic, file=sys.stderr)
        return 1
    print("PROCESS_SOURCE_POLICY: ACCEPT_SELECTED_SOURCE_ONLY sha256=" + hashlib.sha256(raw).hexdigest())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print("PROCESS_SOURCE_POLICY: INCOMPLETE " + str(error), file=sys.stderr)
        raise SystemExit(2)
