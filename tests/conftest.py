"""Shared offline fixtures; builders are ordinary functions in tests.support."""
import pytest

from tests.support.bundles import build_bundle
from tests.support.parent import build_parent
from tests.support.pilot import build_accepted
from tests.support.execution import build_projection, build_packet, build_reporting_study


@pytest.fixture
def small():
    return build_bundle()


@pytest.fixture
def parent_fixture(tmp_path):
    return build_parent(tmp_path)


@pytest.fixture
def accepted(parent_fixture):
    return build_accepted(parent_fixture)


@pytest.fixture(scope='module')
def projection_setup(tmp_path_factory):
    return build_projection(tmp_path_factory.mktemp('runner-projection'))


@pytest.fixture
def packet(tmp_path, projection_setup, monkeypatch):
    return build_packet(tmp_path, projection_setup, monkeypatch)


@pytest.fixture(scope='module')
def reporting_study(tmp_path_factory):
    return build_reporting_study(tmp_path_factory.mktemp('reporting-study'))
