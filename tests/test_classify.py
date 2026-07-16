import pytest
from osint.core.classify import classify


@pytest.mark.parametrize("query,expected", [
    ("example.com", "domain"),
    ("sub.example.co.uk", "domain"),
    ("user@example.com", "email"),
    ("8.8.8.8", "ip"),
    ("192.168.0.1", "ip"),
    ("john_doe", "username"),
    ("ab", "unknown"),          # too short for username
    ("has spaces", "unknown"),
    ("999.999.999.999", "unknown"),  # invalid octets, not an ip
])
def test_classify(query, expected):
    assert classify(query) == expected
