"""Configuration loading.

NOTE: intentionally vulnerable for the security-fix demo.
Fortify flags yaml.load without a safe loader as 'Insecure Deserialization'.
"""
import yaml


def load_config(raw_yaml: str) -> dict:
    # VULN (Fortify: Insecure Deserialization) -> should become yaml.safe_load
    return yaml.safe_load(raw_yaml)
