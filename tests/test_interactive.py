import pytest

from sectool.interactive import parse_selection_spec


def test_parse_single_indices():
    assert parse_selection_spec("1,3,5", n=10) == [0, 2, 4]


def test_parse_range():
    assert parse_selection_spec("2-4", n=10) == [1, 2, 3]


def test_parse_mixed_and_deduplicates_overlap():
    assert parse_selection_spec("1,2-4,4,7", n=10) == [0, 1, 2, 3, 6]


def test_parse_all_keyword():
    assert parse_selection_spec("all", n=5) == [0, 1, 2, 3, 4]


def test_parse_ignores_blank_segments():
    assert parse_selection_spec("1, ,3", n=5) == [0, 2]


@pytest.mark.parametrize(
    "spec",
    ["0", "11", "5-3", "abc", "1-", "-3"],
)
def test_parse_rejects_out_of_bounds_or_malformed(spec):
    with pytest.raises(ValueError):
        parse_selection_spec(spec, n=10)
