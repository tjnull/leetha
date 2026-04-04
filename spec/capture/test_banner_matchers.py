"""Tests for protocol-specific banner matchers."""

from __future__ import annotations

import pytest

from leetha.capture.banner.matchers import match_banner


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

class TestSSH:
    def test_openssh(self):
        payload = b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"
        result = match_banner("ssh", payload)
        assert result is not None
        assert result["service"] == "ssh"
        assert result["version"] == "9.2p1"
        assert "OpenSSH" in result["software"]
        assert result["proto_version"] == "2.0"

    def test_dropbear(self):
        payload = b"SSH-2.0-dropbear_2022.83\r\n"
        result = match_banner("ssh", payload)
        assert result is not None
        assert result["service"] == "ssh"
        assert "dropbear" in result["software"]
        assert result["version"] == "2022.83"

    def test_non_ssh_returns_none(self):
        assert match_banner("ssh", b"HTTP/1.1 200 OK\r\n") is None


# ---------------------------------------------------------------------------
# FTP
# ---------------------------------------------------------------------------

class TestFTP:
    def test_proftpd(self):
        payload = b"220 ProFTPD 1.3.8 Server ready.\r\n"
        result = match_banner("ftp", payload)
        assert result is not None
        assert result["service"] == "ftp"

    def test_vsftpd(self):
        payload = b"220 (vsFTPd 3.0.5)\r\n"
        result = match_banner("ftp", payload)
        assert result is not None
        assert result["service"] == "ftp"
        assert "vsFTPd" in result["software"]

    def test_non_ftp(self):
        assert match_banner("ftp", b"+OK ready\r\n") is None


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

class TestSMTP:
    def test_postfix(self):
        payload = b"220 mail.example.com ESMTP Postfix\r\n"
        result = match_banner("smtp", payload)
        assert result is not None
        assert result["service"] == "smtp"
        assert result["software"] == "Postfix"

    def test_non_smtp(self):
        assert match_banner("smtp", b"220 ProFTPD ready\r\n") is None


# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------

class TestIMAP:
    def test_dovecot(self):
        payload = b"* OK [CAPABILITY IMAP4rev1 SASL-IR] Dovecot ready.\r\n"
        result = match_banner("imap", payload)
        assert result is not None
        assert result["service"] == "imap"

    def test_non_imap(self):
        assert match_banner("imap", b"+OK ready\r\n") is None


# ---------------------------------------------------------------------------
# POP3
# ---------------------------------------------------------------------------

class TestPOP3:
    def test_dovecot(self):
        payload = b"+OK Dovecot ready.\r\n"
        result = match_banner("pop3", payload)
        assert result is not None
        assert result["service"] == "pop3"

    def test_non_pop3(self):
        assert match_banner("pop3", b"* OK IMAP ready\r\n") is None


# ---------------------------------------------------------------------------
# Telnet
# ---------------------------------------------------------------------------

class TestTelnet:
    def test_iac_bytes(self):
        payload = b"\xff\xfb\x01\xff\xfb\x03"
        result = match_banner("telnet", payload)
        assert result is not None
        assert result["service"] == "telnet"

    def test_iac_fd(self):
        payload = b"\xff\xfd\x18"
        result = match_banner("telnet", payload)
        assert result is not None
        assert result["service"] == "telnet"

    def test_login_prompt(self):
        payload = b"Ubuntu 22.04 LTS\r\nlogin: "
        result = match_banner("telnet", payload)
        assert result is not None
        assert result["service"] == "telnet"

    def test_non_telnet(self):
        assert match_banner("telnet", b"SSH-2.0-OpenSSH\r\n") is None


# ---------------------------------------------------------------------------
# VNC
# ---------------------------------------------------------------------------

class TestVNC:
    def test_rfb(self):
        payload = b"RFB 003.008\n"
        result = match_banner("vnc", payload)
        assert result is not None
        assert result["service"] == "vnc"
        assert result["version"] == "003.008"

    def test_non_vnc(self):
        assert match_banner("vnc", b"SSH-2.0-test\r\n") is None


# ---------------------------------------------------------------------------
# IRC
# ---------------------------------------------------------------------------

class TestIRC:
    def test_notice(self):
        payload = b":server NOTICE * :Looking up your hostname\r\n"
        result = match_banner("irc", payload)
        assert result is not None
        assert result["service"] == "irc"

    def test_numeric(self):
        payload = b":irc.example.com 001 nick :Welcome\r\n"
        result = match_banner("irc", payload)
        assert result is not None
        assert result["service"] == "irc"


# ---------------------------------------------------------------------------
# MySQL
# ---------------------------------------------------------------------------

class TestMySQL:
    def test_mysql_8(self):
        version = b"8.0.35"
        pkt_len = len(version) + 2  # proto_ver + version + null
        payload = (
            pkt_len.to_bytes(3, "little")
            + b"\x00"  # sequence
            + b"\x0a"  # protocol version 10
            + version
            + b"\x00"  # null terminator
        )
        result = match_banner("mysql", payload)
        assert result is not None
        assert result["service"] == "mysql"
        assert result["software"] == "MySQL"
        assert result["version"] == "8.0.35"

    def test_mariadb(self):
        version = b"5.5.5-10.11.4-MariaDB"
        pkt_len = len(version) + 2
        payload = (
            pkt_len.to_bytes(3, "little")
            + b"\x00"
            + b"\x0a"
            + version
            + b"\x00"
        )
        result = match_banner("mysql", payload)
        assert result is not None
        assert result["service"] == "mysql"
        assert result["software"] == "MariaDB"
        assert result["version"] == "10.11.4"

    def test_non_mysql(self):
        assert match_banner("mysql", b"\x00\x00\x00\x00\x09test\x00") is None


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------

class TestPostgreSQL:
    def test_auth_ok(self):
        # R message (AuthenticationOk): R + int32(8) + int32(0)
        payload = b"R\x00\x00\x00\x08\x00\x00\x00\x00"
        result = match_banner("postgresql", payload)
        assert result is not None
        assert result["service"] == "postgresql"

    def test_non_postgresql(self):
        assert match_banner("postgresql", b"\x04\x00\x00") is None


# ---------------------------------------------------------------------------
# MSSQL
# ---------------------------------------------------------------------------

class TestMSSQL:
    def test_tds_response(self):
        payload = b"\x04\x01\x00\x25\x00\x00\x01\x00"
        result = match_banner("mssql", payload)
        assert result is not None
        assert result["service"] == "mssql"

    def test_non_mssql(self):
        assert match_banner("mssql", b"\x03\x00\x00") is None


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------

class TestMongoDB:
    def test_op_reply(self):
        # 16-byte header with opcode 1 at bytes 12-15 (LE)
        payload = b"\x00" * 12 + b"\x01\x00\x00\x00" + b"\x00" * 16
        result = match_banner("mongodb", payload)
        assert result is not None
        assert result["service"] == "mongodb"

    def test_op_msg(self):
        payload = b"\x00" * 12 + b"\xdd\x07\x00\x00" + b"\x00" * 16
        result = match_banner("mongodb", payload)
        assert result is not None
        assert result["service"] == "mongodb"

    def test_non_mongodb(self):
        assert match_banner("mongodb", b"\x00" * 16) is None


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------

class TestRedis:
    def test_pong(self):
        payload = b"+PONG\r\n"
        result = match_banner("redis", payload)
        assert result is not None
        assert result["service"] == "redis"

    def test_error(self):
        payload = b"-NOAUTH Authentication required.\r\n"
        result = match_banner("redis", payload)
        assert result is not None
        assert result["service"] == "redis"

    def test_with_version(self):
        payload = b"$100\r\nredis_version:7.2.4\r\nother_field:value\r\n"
        result = match_banner("redis", payload)
        assert result is not None
        assert result["version"] == "7.2.4"

    def test_non_redis(self):
        assert match_banner("redis", b"HTTP/1.1 200\r\n") is None


# ---------------------------------------------------------------------------
# SMB
# ---------------------------------------------------------------------------

class TestSMB:
    def test_smb2(self):
        payload = b"\x00\x00\x00\x40" + b"\xfeSMB" + b"\x00" * 60
        result = match_banner("smb", payload)
        assert result is not None
        assert result["service"] == "smb"
        assert result["smb_version"] == "2"

    def test_smb1(self):
        payload = b"\x00\x00\x00\x40" + b"\xffSMB" + b"\x00" * 60
        result = match_banner("smb", payload)
        assert result is not None
        assert result["service"] == "smb"
        assert result["smb_version"] == "1"

    def test_non_smb(self):
        assert match_banner("smb", b"\x00\x00\x00\x40\x00\x00\x00\x00") is None


# ---------------------------------------------------------------------------
# RDP
# ---------------------------------------------------------------------------

class TestRDP:
    def test_connection_confirm(self):
        payload = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        result = match_banner("rdp", payload)
        assert result is not None
        assert result["service"] == "rdp"

    def test_non_rdp(self):
        assert match_banner("rdp", b"\x04\x00\x00\x13\x0e\xd0") is None


# ---------------------------------------------------------------------------
# IPP
# ---------------------------------------------------------------------------

class TestIPP:
    def test_ipp_response(self):
        payload = b"HTTP/1.1 200 OK\r\nServer: EPSON-Printer\r\nContent-Type: application/ipp\r\n\r\n"
        result = match_banner("ipp", payload)
        assert result is not None
        assert result["service"] == "ipp"
        assert result["software"] == "EPSON-Printer"

    def test_non_ipp(self):
        assert match_banner("ipp", b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n") is None


# ---------------------------------------------------------------------------
# JetDirect
# ---------------------------------------------------------------------------

class TestJetDirect:
    def test_pjl(self):
        payload = b"@PJL INFO STATUS\r\n"
        result = match_banner("jetdirect", payload)
        assert result is not None
        assert result["service"] == "jetdirect"

    def test_non_jetdirect(self):
        assert match_banner("jetdirect", b"HTTP/1.1 200\r\n") is None


# ---------------------------------------------------------------------------
# LPD
# ---------------------------------------------------------------------------

class TestLPD:
    def test_printer_keyword(self):
        payload = b"printer ready\n"
        result = match_banner("lpd", payload)
        assert result is not None
        assert result["service"] == "lpd"

    def test_non_lpd(self):
        assert match_banner("lpd", b"SSH-2.0-test\r\n") is None


# ---------------------------------------------------------------------------
# Dispatch edge cases
# ---------------------------------------------------------------------------

class TestDispatch:
    def test_unknown_service(self):
        assert match_banner("unknown_protocol", b"some data") is None

    def test_empty_payload(self):
        assert match_banner("ssh", b"") is None

    def test_case_insensitive_service(self):
        payload = b"SSH-2.0-OpenSSH_9.2p1\r\n"
        result = match_banner("SSH", payload)
        assert result is not None
        assert result["service"] == "ssh"
