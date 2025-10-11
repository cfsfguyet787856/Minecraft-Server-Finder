import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mcsmartscan import utils


def test_ip_range_size_is_order_agnostic():
    assert utils.ip_range_size("192.168.0.1", "192.168.0.10") == 10
    assert utils.ip_range_size("192.168.0.10", "192.168.0.1") == 10


def test_ip_range_generator_sequential():
    ips = list(utils.ip_range_generator("10.0.0.1", "10.0.0.3"))
    assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


@pytest.mark.parametrize(
    "start,end,expected",
    [
        (
            "192.168.1.1",
            "192.168.1.5",
            [
                "192.168.1.1",
                "192.168.1.2",
                "192.168.1.1",
                "192.168.1.2",
                "192.168.1.5",
                "192.168.1.5",
            ],
        ),
        (
            "10.0.0.5",
            "10.0.0.1",
            [
                "10.0.0.1",
                "10.0.0.2",
                "10.0.0.1",
                "10.0.0.2",
                "10.0.0.5",
                "10.0.0.5",
            ],
        ),
    ],
)
def test_permuted_index_generator_is_deterministic(start, end, expected):
    seed = b"pytest-seed"
    output = list(utils.permuted_index_generator(start, end, seed=seed))
    assert output == expected
    valid = set(utils.ip_range_generator(start, end))
    assert all(value in valid for value in output)
