"""Installed package resources; experiment inputs remain explicit filesystem paths."""
from importlib.resources import files
from pathlib import Path


def resource(name):
    """Locate a packaged resource in a normal source or wheel installation."""
    return Path(str(files('optimization_vuln_analysis').joinpath(name)))
