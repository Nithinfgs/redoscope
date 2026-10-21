"""Deliberately vulnerable regexes used for the redoscope demo."""

import re

# Classic nested quantifier: exponential.
USERNAME = re.compile(r"^(\w+\s?)+$")

# Two adjacent loops over the same characters: quadratic.
NUMBERS = re.compile(r"^\d+\d+$")

# Looks scary, is fine: each character can be consumed only one way.
QUOTED = re.compile(r'^"([^"\\]|\\.)*"$')

# Safe: the dot separates iterations.
VERSION = re.compile(r"^(\d+\.)+\d+$")

# Known and accepted, silenced inline.
LEGACY = re.compile(r"^(a+)+$")  # redoscope: ignore
