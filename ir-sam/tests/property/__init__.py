"""Hypothesis property-based test layer.

Strategies live alongside the tests so each test file is self-contained.
Hypothesis settings are tuned per test using ``@settings(max_examples=...)``;
``--hypothesis-seed`` is respected for reproducibility.
"""
