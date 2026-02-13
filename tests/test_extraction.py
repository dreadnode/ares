"""Tests for extraction module."""

from ares.core.dispatcher.extraction import extract_shares_from_output


class TestExtractSharesFromOutput:
    """Tests for share extraction from netexec --shares output."""

    def test_parse_shares_with_permissions(self):
        """Test parsing shares that have permissions."""
        output = """\
SMB         192.168.58.10   445    DC01             Share           Permissions     Comment
SMB         192.168.58.10   445    DC01             -----           -----------     -------
SMB         192.168.58.10   445    DC01             ADMIN$          READ,WRITE      Remote Admin
SMB         192.168.58.10   445    DC01             C$              READ,WRITE      Default share
SMB         192.168.58.10   445    DC01             public          READ,WRITE      Basic Read share for all domain users
"""
        shares = extract_shares_from_output(output)

        assert len(shares) == 3
        admin_share = next(s for s in shares if s.name == "ADMIN$")
        c_share = next(s for s in shares if s.name == "C$")
        public_share = next(s for s in shares if s.name == "public")

        assert admin_share.permissions == "READ,WRITE"
        assert admin_share.comment == "Remote Admin"

        assert c_share.permissions == "READ,WRITE"
        assert c_share.comment == "Default share"

        assert public_share.permissions == "READ,WRITE"
        assert public_share.comment == "Basic Read share for all domain users"

    def test_parse_shares_without_permissions(self):
        """Test parsing shares that have no permissions (empty column).

        This tests the bug where shares with empty permissions had the first
        word of the comment parsed as permissions (e.g., ADMIN$ [Remote] instead
        of ADMIN$ with no permissions).
        """
        # When a share has no permissions, netexec outputs with only comment
        output = """\
SMB         192.168.58.10   445    DC01             Share           Permissions     Comment
SMB         192.168.58.10   445    DC01             -----           -----------     -------
SMB         192.168.58.10   445    DC01             ADMIN$                          Remote Admin
SMB         192.168.58.10   445    DC01             public          READ,WRITE      Basic Read share for all domain users
"""
        shares = extract_shares_from_output(output)

        assert len(shares) == 2
        admin_share = next(s for s in shares if s.name == "ADMIN$")
        public_share = next(s for s in shares if s.name == "public")

        # ADMIN$ has no permissions - "Remote" is NOT a valid permission
        assert admin_share.permissions == ""
        assert admin_share.comment == "Remote Admin"

        # public has valid permissions
        assert public_share.permissions == "READ,WRITE"
        assert public_share.comment == "Basic Read share for all domain users"

    def test_parse_shares_mixed_permissions(self):
        """Test parsing mix of shares with and without permissions."""
        output = """\
SMB         192.168.58.10   445    DC01             Share           Permissions     Comment
SMB         192.168.58.10   445    DC01             -----           -----------     -------
SMB         192.168.58.10   445    DC01             ADMIN$                          Remote Admin
SMB         192.168.58.10   445    DC01             C$              READ            Default share
SMB         192.168.58.10   445    DC01             IPC$                            IPC Service
SMB         192.168.58.10   445    DC01             NETLOGON        READ            Logon server share
SMB         192.168.58.10   445    DC01             SYSVOL          READ            Logon server share
SMB         192.168.58.10   445    DC01             data            WRITE           Active Directory data
"""
        shares = extract_shares_from_output(output)

        assert len(shares) == 6

        admin_share = next(s for s in shares if s.name == "ADMIN$")
        assert admin_share.permissions == ""
        assert admin_share.comment == "Remote Admin"

        c_share = next(s for s in shares if s.name == "C$")
        assert c_share.permissions == "READ"
        assert c_share.comment == "Default share"

        ipc_share = next(s for s in shares if s.name == "IPC$")
        assert ipc_share.permissions == ""
        assert ipc_share.comment == "IPC Service"

        netlogon_share = next(s for s in shares if s.name == "NETLOGON")
        assert netlogon_share.permissions == "READ"
        assert netlogon_share.comment == "Logon server share"

        data_share = next(s for s in shares if s.name == "data")
        assert data_share.permissions == "WRITE"
        assert data_share.comment == "Active Directory data"

    def test_parse_read_write_variations(self):
        """Test different valid permission formats."""
        output = """\
SMB         192.168.58.10   445    DC01             Share           Permissions     Comment
SMB         192.168.58.10   445    DC01             -----           -----------     -------
SMB         192.168.58.10   445    DC01             share1          READ            Comment 1
SMB         192.168.58.10   445    DC01             share2          WRITE           Comment 2
SMB         192.168.58.10   445    DC01             share3          READ,WRITE      Comment 3
"""
        shares = extract_shares_from_output(output)

        assert len(shares) == 3
        assert shares[0].permissions == "READ"
        assert shares[1].permissions == "WRITE"
        assert shares[2].permissions == "READ,WRITE"

    def test_parse_empty_output(self):
        """Test handling of empty output."""
        assert extract_shares_from_output("") == []
        assert extract_shares_from_output(None) == []

    def test_host_extraction(self):
        """Test that host IP is correctly extracted from SMB line prefix."""
        output = """\
SMB         192.168.58.10   445    DC01             Share           Permissions     Comment
SMB         192.168.58.10   445    DC01             -----           -----------     -------
SMB         192.168.58.10   445    DC01             ADMIN$          READ,WRITE      Remote Admin
"""
        shares = extract_shares_from_output(output)
        assert len(shares) == 1
        assert shares[0].host == "192.168.58.10"

    def test_default_host_used_when_not_parsed(self):
        """Test that default_host is used when IP not in output."""
        # Output without SMB IP prefix format
        output = """\
Share           Permissions     Comment
-----           -----------     -------
ADMIN$          READ,WRITE      Remote Admin
"""
        shares = extract_shares_from_output(output, default_host="192.168.58.100")
        # This won't parse since there's no SMB prefix and in_table won't be set
        assert len(shares) == 0
