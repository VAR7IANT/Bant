import pytest

from tests.fakes import FakeHost


@pytest.fixture
def host(tmp_path):
    return FakeHost(tmp_path / "root")


@pytest.fixture
def ctx(host):
    return host.make_ctx()
