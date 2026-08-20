# tests/model/test_remote.py
"""Row coverage for parse_remote lives in tests/specs/frames.py
(REMOTE-01..REMOTE-07). Only the hash-consistency contract and the
bare-"::" literal are not expressible as rows and stay here."""

import pytest
from hcs_sg_iac.model.remote import RemoteCidr, parse_remote


def test_bare_ip_equals_explicit_32():
    assert parse_remote("203.0.113.7") == parse_remote("203.0.113.7/32")
    assert (
        len({parse_remote("203.0.113.7"), RemoteCidr(cidr="203.0.113.7/32")})
        == 1
    )


def test_ipv6_unspecified_address_rejected():
    with pytest.raises(ValueError, match="IPv6"):
        parse_remote("::")  # REMOTE-05/05.a carry 2001:db8::/32 and ::1
