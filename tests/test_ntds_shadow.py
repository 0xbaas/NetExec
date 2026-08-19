"""Tests for nxc/modules/ntds_shadow.py.

All DiskShadow output parsing and script construction is tested in isolation.
The integration suite mocks every NetExec boundary without reaching the network.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from nxc.modules.ntds_shadow import (
    NXCModule,
    build_cleanup_script,
    build_create_script,
    build_delete_only_script,
    parse_alias_guid,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

# gen_random_string is patched to return RUN_ID in all integration tests.
RUN_ID = "helloabc"
ALIAS = f"vss{RUN_ID}"
GUID = "12345678-1234-1234-1234-123456789ABC"
GUID_NORM = GUID.upper()
DRIVE = "Z"
STAGING = f"C:\\Windows\\Temp\\nxc_{RUN_ID}"

# DiskShadow stdout that satisfies both GUID parsing and exposure verification.
# The "successfully exposed as Z:\." line uses a trailing backslash-period;
# "Z:." or "Z:\" are failure forms rejected by _EXPOSE_CONFIRM_RE.
VALID_DS_STDOUT = f"DISKSHADOW> create\r\n  -> %{ALIAS}% = {{{GUID}}}\r\nDISKSHADOW> expose %{ALIAS}% {DRIVE}:\r\n    The shadow copy was successfully exposed as {DRIVE}:\\.\r\n"

# DiskShadow stdout with a valid GUID but no expose confirmation line.
DS_NO_EXPOSE = f"DISKSHADOW> create\r\n  -> %{ALIAS}% = {{{GUID}}}\r\n"

# Expected cleanup transcript that satisfies both GUID and count verification.
VALID_CLEANUP_STDOUT = (
    f"Deleting shadow copy {{{GUID_NORM}}}...\r\n1 shadow copy deleted.\r\n"
)

PRIV_ENABLED = '"SeBackupPrivilege","Back up files and directories","Enabled"\n'
PRIV_DISABLED = '"SeBackupPrivilege","Back up files and directories","Disabled"\n'
DRIVES_CZ = "C:\\\nD:\\\n"  # Z free -> _pick_drive returns "Z"
METADATA_CAB = f"{STAGING}\\metadata.cab"

# Format 2 (env-var notice) DiskShadow line - exact real Blackfield format.
# No leading "->"; wording is "shadow ID" (not "shadow copy").
ENVVAR_LINE = f"Alias {ALIAS} for shadow ID {{{GUID}}} set as environment variable.\r\n"

# Exact Blackfield lab line, kept verbatim for golden-path parsing test:
REAL_ENVVAR_LINE = (
    "Alias vsscgkkbvmp for shadow ID {fc025741-1da8-4a38-b7a7-114458ffce08}"
    " set as environment variable.\r\n"
)
REAL_ALIAS = "vsscgkkbvmp"
REAL_GUID_NORM = "FC025741-1DA8-4A38-B7A7-114458FFCE08"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ps_result(stdout="", stderr="", rc=0, had_errors=False, error_msgs=None):
    """Return the (ps_stdout, streams, had_errors) tuple that _run_cmd expects.

    Mirrors the real connection.conn.execute_ps() return value:
        tuple[str, PSDataStreams, bool]
    streams is a MagicMock whose .error attribute is a list of plain strings so
    that "str(e) for e in streams.error" works without further setup.
    """
    streams = MagicMock()
    streams.error = list(error_msgs or [])
    payload = json.dumps({"O": stdout, "E": stderr, "C": rc})
    return (payload, streams, had_errors)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def module():
    return NXCModule()


@pytest.fixture
def mock_log():
    log = MagicMock()
    log.display = MagicMock()
    log.success = MagicMock()
    log.fail = MagicMock()
    log.debug = MagicMock()
    log.highlight = MagicMock()
    return log


def make_ctx(log):
    ctx = MagicMock()
    ctx.log = log
    return ctx


# ---------------------------------------------------------------------------
# TestParseAliasGuid
# ---------------------------------------------------------------------------


class TestParseAliasGuid:
    def test_returns_normalised_guid_for_valid_single_match(self):
        stdout = f"  -> %{ALIAS}% = {{{GUID.lower()}}}\r\n"
        assert parse_alias_guid(stdout, ALIAS) == GUID_NORM

    def test_returns_none_when_alias_absent(self):
        stdout = "  -> %otheralias% = {AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}\r\n"
        assert parse_alias_guid(stdout, ALIAS) is None

    def test_returns_none_for_empty_stdout(self):
        assert parse_alias_guid("", ALIAS) is None

    def test_raises_value_error_on_duplicate_alias(self):
        stdout = f"  -> %{ALIAS}% = {{{GUID}}}\r\n  -> %{ALIAS}% = {{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}}\r\n"
        with pytest.raises(ValueError, match="Ambiguous"):
            parse_alias_guid(stdout, ALIAS)

    def test_alias_match_is_case_insensitive(self):
        stdout = f"  -> %{ALIAS.upper()}% = {{{GUID}}}\r\n"
        assert parse_alias_guid(stdout, ALIAS.lower()) == GUID_NORM

    def test_guid_is_uppercased_in_return_value(self):
        stdout = f"  -> %{ALIAS}% = {{{GUID.lower()}}}\r\n"
        result = parse_alias_guid(stdout, ALIAS)
        assert result == result.upper()

    # -- Format 2 (env-var notice) - confirmed real Blackfield format --

    def test_returns_guid_from_real_blackfield_envvar_line(self):
        """Golden test: exact Blackfield stdout line must parse to the correct GUID."""
        assert parse_alias_guid(REAL_ENVVAR_LINE, REAL_ALIAS) == REAL_GUID_NORM

    def test_returns_guid_from_envvar_line_format(self):
        """Format 2: 'Alias <alias> for shadow ID {GUID} set as environment variable.'"""
        assert parse_alias_guid(ENVVAR_LINE, ALIAS) == GUID_NORM

    def test_envvar_format_alias_match_is_case_insensitive(self):
        line = f"Alias {ALIAS.upper()} for shadow ID {{{GUID}}} set as environment variable.\r\n"
        assert parse_alias_guid(line, ALIAS.lower()) == GUID_NORM

    def test_same_guid_in_both_formats_is_not_ambiguous(self):
        """The same GUID in Format 1 and Format 2 must be deduplicated, not raise ValueError."""
        both = f"  -> %{ALIAS}% = {{{GUID}}}\r\n" + ENVVAR_LINE
        assert parse_alias_guid(both, ALIAS) == GUID_NORM

    def test_different_guids_across_formats_raises_value_error(self):
        """Distinct GUIDs from Format 1 and Format 2 for the same alias must raise ValueError."""
        other_guid = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
        mixed = (
            f"  -> %{ALIAS}% = {{{GUID}}}\r\n"
            f"Alias {ALIAS} for shadow ID {{{other_guid}}} set as environment variable.\r\n"
        )
        with pytest.raises(ValueError, match="Ambiguous"):
            parse_alias_guid(mixed, ALIAS)

    def test_envvar_line_for_other_alias_is_ignored(self):
        """An env-var line for a different alias must not be returned."""
        other_line = f"Alias otheralias for shadow ID {{{GUID}}} set as environment variable.\r\n"
        assert parse_alias_guid(other_line, ALIAS) is None

    def test_returns_none_when_alias_absent_in_both_formats(self):
        both = (
            "  -> %otheralias% = {AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}\r\n"
            "Alias otheralias for shadow ID {AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA} set as environment variable.\r\n"
        )
        assert parse_alias_guid(both, ALIAS) is None


# ---------------------------------------------------------------------------
# TestScriptBuilders
# ---------------------------------------------------------------------------


class TestScriptBuilders:
    def test_create_script_uses_crlf_line_endings(self):
        script = build_create_script(ALIAS, DRIVE, METADATA_CAB)
        assert "\r\n" in script

    def test_create_script_contains_alias_and_drive_letter(self):
        script = build_create_script(ALIAS, DRIVE, METADATA_CAB)
        assert ALIAS in script
        assert f"{DRIVE}:" in script

    def test_create_script_contains_set_metadata_line(self):
        """DiskShadow create script must use 'set metadata <path>', not bare 'metadata <path>'."""
        script = build_create_script(ALIAS, DRIVE, METADATA_CAB)
        assert f"set metadata {METADATA_CAB}" in script

    def test_cleanup_script_contains_exact_guid_and_unexpose(self):
        script = build_cleanup_script(DRIVE, GUID_NORM)
        assert f"delete shadows id {{{GUID_NORM}}}" in script
        assert f"unexpose {DRIVE}:" in script

    def test_delete_only_script_has_no_unexpose_command(self):
        script = build_delete_only_script(GUID_NORM)
        assert f"delete shadows id {{{GUID_NORM}}}" in script
        assert "unexpose" not in script

    @pytest.mark.parametrize(
        "script",
        [
            build_create_script(ALIAS, DRIVE, METADATA_CAB),
            build_cleanup_script(DRIVE, GUID_NORM),
            build_delete_only_script(GUID_NORM),
        ],
        ids=["create", "cleanup", "delete_only"],
    )
    def test_no_script_contains_delete_shadows_all(self, script):
        assert "delete shadows all" not in script.lower()


# ---------------------------------------------------------------------------
# TestNativeAdapter
# ---------------------------------------------------------------------------


class TestNativeAdapter:
    """Unit tests for the _run_cmd PS adapter."""

    def test_returns_stdout_stderr_and_integer_rc(self, module):
        """Adapter unpacks the execute_ps 3-tuple, parses JSON, coerces rc to int."""
        conn = MagicMock()
        conn.conn.execute_ps.return_value = _make_ps_result("hello\n", "err\n", 42)
        out, err, rc = module._run_cmd(conn, "echo hello")
        assert out == "hello\n"
        assert err == "err\n"
        assert rc == 42
        assert isinstance(rc, int)

    def test_raises_on_none_stdout(self, module):
        """None ps_stdout in the returned tuple must raise RuntimeError."""
        conn = MagicMock()
        conn.conn.execute_ps.return_value = (None, MagicMock(), False)
        with pytest.raises(RuntimeError, match="No response"):
            module._run_cmd(conn, "whoami")

    def test_raises_on_had_errors_true(self, module):
        """had_errors=True must raise RuntimeError regardless of ps_stdout content."""
        conn = MagicMock()
        conn.conn.execute_ps.return_value = _make_ps_result(
            had_errors=True, error_msgs=["Access denied"]
        )
        with pytest.raises(RuntimeError, match="errors"):
            module._run_cmd(conn, "whoami")

    def test_had_errors_includes_error_stream_messages(self, module):
        """Error stream content must appear in the RuntimeError message."""
        conn = MagicMock()
        conn.conn.execute_ps.return_value = _make_ps_result(
            had_errors=True, error_msgs=["Cannot connect to remote server"]
        )
        with pytest.raises(RuntimeError, match="Cannot connect"):
            module._run_cmd(conn, "whoami")

    def test_raises_on_malformed_return_shape(self, module):
        """execute_ps returning a non-3-tuple must raise RuntimeError."""
        conn = MagicMock()
        conn.conn.execute_ps.return_value = ("only_one_element",)
        with pytest.raises(RuntimeError, match="Unexpected"):
            module._run_cmd(conn, "whoami")

    def test_raises_on_invalid_json_in_stdout(self, module):
        """Unparseable JSON in ps_stdout must raise RuntimeError."""
        conn = MagicMock()
        conn.conn.execute_ps.return_value = ("not valid json", MagicMock(), False)
        with pytest.raises(RuntimeError, match="Failed to parse"):
            module._run_cmd(conn, "whoami")

    def test_raises_on_missing_json_fields(self, module):
        """JSON missing the exit code field must raise RuntimeError."""
        conn = MagicMock()
        conn.conn.execute_ps.return_value = (
            json.dumps({"foo": "bar"}),
            MagicMock(),
            False,
        )
        with pytest.raises(RuntimeError, match="Failed to parse"):
            module._run_cmd(conn, "whoami")

    def test_privilege_detected_from_adapter_stdout(self, module, mock_log):
        """_check_privilege reads privilege state from _run_cmd stdout via correct tuple unpacking."""
        conn = MagicMock()
        conn.conn.execute_ps.return_value = _make_ps_result(PRIV_ENABLED)
        assert module._check_privilege(mock_log, conn) is True


# ---------------------------------------------------------------------------
# TestCheckPrivilege
# ---------------------------------------------------------------------------


class TestCheckPrivilege:
    def test_enabled_privilege_returns_true(self, module, mock_log):
        conn = MagicMock()
        conn.conn.execute_ps.return_value = _make_ps_result(PRIV_ENABLED)
        assert module._check_privilege(mock_log, conn) is True
        mock_log.success.assert_called_once()

    @pytest.mark.parametrize(
        ("stdout", "label"),
        [
            (PRIV_DISABLED, "disabled"),
            ('"SeAuditPrivilege","Generate security audits","Enabled"\n', "absent"),
        ],
        ids=["disabled", "absent"],
    )
    def test_privilege_returns_false_when_not_enabled(
        self, module, mock_log, stdout, label
    ):
        conn = MagicMock()
        conn.conn.execute_ps.return_value = _make_ps_result(stdout)
        assert module._check_privilege(mock_log, conn) is False
        mock_log.fail.assert_called_once()

    def test_execute_ps_exception_returns_false(self, module, mock_log):
        """Transport exception from execute_ps must be caught and logged."""
        conn = MagicMock()
        conn.conn.execute_ps.side_effect = RuntimeError("WinRM transport failure")
        assert module._check_privilege(mock_log, conn) is False
        mock_log.fail.assert_called_once()


# ---------------------------------------------------------------------------
# TestPickDrive
# ---------------------------------------------------------------------------


class TestPickDrive:
    def test_returns_z_when_only_cd_occupied(self, module, mock_log):
        conn = MagicMock()
        conn.execute.return_value = DRIVES_CZ
        assert module._pick_drive(mock_log, conn) == "Z"

    def test_skips_z_when_occupied_and_picks_y(self, module, mock_log):
        conn = MagicMock()
        conn.execute.return_value = "C:\\\nD:\\\nZ:\\\n"
        assert module._pick_drive(mock_log, conn) == "Y"

    def test_returns_none_when_d_through_z_all_occupied(self, module, mock_log):
        conn = MagicMock()
        conn.execute.return_value = (
            "\n".join(f"{letter}:\\" for letter in "DCEFGHIJKLMNOPQRSTUVWXYZ") + "\n"
        )
        result = module._pick_drive(mock_log, conn)
        assert result is None
        mock_log.fail.assert_called_once()


# ---------------------------------------------------------------------------
# TestUpload
# ---------------------------------------------------------------------------


class TestUpload:
    def test_successful_upload_returns_true(self, module, mock_log):
        conn = MagicMock()
        conn.conn.copy = MagicMock()
        assert module._upload(mock_log, conn, "content\r\n", "C:\\tmp\\x.dsh") is True
        conn.conn.copy.assert_called_once()

    def test_copy_failure_returns_false_and_logs(self, module, mock_log):
        conn = MagicMock()
        conn.conn.copy.side_effect = OSError("network error")
        assert module._upload(mock_log, conn, "content\r\n", "C:\\tmp\\x.dsh") is False
        mock_log.fail.assert_called_once()


# ---------------------------------------------------------------------------
# TestDownload
# ---------------------------------------------------------------------------


class TestDownload:
    def test_success_with_matching_sizes(self, module, mock_log, tmp_path):
        """Fetch succeeds and local size matches remote -> returns True."""
        local = str(tmp_path / "ntds.dit")

        conn = MagicMock()
        conn.execute.return_value = "1024\n"

        def fake_fetch(remote, local_p):
            with open(local_p, "wb") as f:
                f.write(b"x" * 1024)

        conn.conn.fetch.side_effect = fake_fetch

        result = module._download(
            mock_log, conn, "C:\\stage\\ntds.dit", local, "NTDS.dit"
        )
        assert result is True
        mock_log.success.assert_called_once()
        assert "1024" in mock_log.success.call_args[0][0]

    def test_fetch_exception_returns_false(self, module, mock_log, tmp_path):
        local = str(tmp_path / "ntds.dit")
        conn = MagicMock()
        conn.execute.return_value = "1024\n"
        conn.conn.fetch.side_effect = Exception("connection reset")
        assert (
            module._download(mock_log, conn, "C:\\stage\\ntds.dit", local, "NTDS.dit")
            is False
        )
        mock_log.fail.assert_called_once()

    def test_size_mismatch_returns_false(self, module, mock_log, tmp_path):
        """Remote reports 2048 bytes but local file has 512 bytes -> False."""
        local = str(tmp_path / "ntds.dit")
        conn = MagicMock()
        conn.execute.return_value = "2048\n"

        def fake_fetch(remote, local_p):
            with open(local_p, "wb") as f:
                f.write(b"x" * 512)

        conn.conn.fetch.side_effect = fake_fetch
        assert (
            module._download(mock_log, conn, "C:\\stage\\ntds.dit", local, "NTDS.dit")
            is False
        )
        assert any("mismatch" in str(c) for c in mock_log.fail.call_args_list)

    @pytest.mark.parametrize(
        "ps_out",
        [
            None,
            "0\n",
            "not_a_number\n",
        ],
        ids=["none", "zero", "non_numeric"],
    )
    def test_bad_remote_size_returns_false_without_fetch(
        self, module, mock_log, tmp_path, ps_out
    ):
        """None, zero, or non-numeric PS size query -> fail immediately without fetching."""
        local = str(tmp_path / "ntds.dit")
        conn = MagicMock()
        conn.execute.return_value = ps_out
        assert (
            module._download(mock_log, conn, "C:\\stage\\ntds.dit", local, "NTDS.dit")
            is False
        )
        conn.conn.fetch.assert_not_called()
        mock_log.fail.assert_called_once()

    def test_fetch_exception_removes_partial_local_file(
        self, module, mock_log, tmp_path
    ):
        """A partial local file left by a failed fetch must be removed."""
        local = str(tmp_path / "ntds.dit")
        conn = MagicMock()
        conn.execute.return_value = "1024\n"

        def partial_then_raise(remote, local_p):
            with open(local_p, "wb") as f:
                f.write(b"x" * 512)
            raise OSError("connection reset")

        conn.conn.fetch.side_effect = partial_then_raise
        assert (
            module._download(mock_log, conn, "C:\\stage\\ntds.dit", local, "NTDS.dit")
            is False
        )
        assert not os.path.exists(local), (
            "partial file must be removed after fetch exception"
        )

    def test_size_mismatch_removes_local_file(self, module, mock_log, tmp_path):
        """After a size mismatch the local file must be removed."""
        local = str(tmp_path / "ntds.dit")
        conn = MagicMock()
        conn.execute.return_value = "2048\n"

        def fake_fetch(remote, local_p):
            with open(local_p, "wb") as f:
                f.write(b"x" * 512)

        conn.conn.fetch.side_effect = fake_fetch
        assert (
            module._download(mock_log, conn, "C:\\stage\\ntds.dit", local, "NTDS.dit")
            is False
        )
        assert not os.path.exists(local), "mismatched file must be removed"


# ---------------------------------------------------------------------------
# TestCleanup
# ---------------------------------------------------------------------------


class TestCleanup:
    """Cleanup correctness, independence, and GUID-gating."""

    def _base_conn(self, execute_ps_seq=None):
        conn = MagicMock()
        conn.conn = MagicMock()
        if execute_ps_seq is not None:
            conn.conn.execute_ps.side_effect = execute_ps_seq
        else:
            # Default: confirmed cleanup transcript returned for every call.
            conn.conn.execute_ps.return_value = _make_ps_result(VALID_CLEANUP_STDOUT)
        conn.conn.copy = MagicMock()
        return conn

    # -- script choice based on expose_reported --

    def test_uses_cleanup_script_when_expose_reported_true(self, module, mock_log):
        conn = self._base_conn()
        seen = []

        def capture(log, c, content, path):
            seen.append(content)
            return True

        with patch.object(module, "_upload", side_effect=capture):
            module._cleanup(mock_log, conn, GUID_NORM, DRIVE, True, STAGING)
        assert any("unexpose" in s for s in seen), "expected unexpose in cleanup script"

    def test_uses_delete_only_script_when_expose_reported_false(self, module, mock_log):
        conn = self._base_conn()
        seen = []

        def capture(log, c, content, path):
            seen.append(content)
            return True

        with patch.object(module, "_upload", side_effect=capture):
            module._cleanup(mock_log, conn, GUID_NORM, DRIVE, False, STAGING)
        assert not any("unexpose" in s for s in seen), (
            "unexpected unexpose in delete-only script"
        )

    # -- transcript confirmation --

    def test_logs_debug_on_confirmed_deletion(self, module, mock_log):
        conn = self._base_conn()
        with patch.object(module, "_upload", return_value=True):
            module._cleanup(mock_log, conn, GUID_NORM, DRIVE, True, STAGING)
        mock_log.debug.assert_any_call("Snapshot deleted successfully")

    @pytest.mark.parametrize(
        ("ds_stdout", "ds_rc"),
        [
            ("Something failed.", 1),
            ("1 shadow copy deleted.", 0),
            (
                "Deleting shadow copy {AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}...\r\n1 shadow copy deleted.\r\n",
                0,
            ),
        ],
        ids=["bad_rc", "count_no_guid", "wrong_guid"],
    )
    def test_unconfirmed_transcript_logs_fail_not_debug(
        self, module, mock_log, ds_stdout, ds_rc
    ):
        """Unconfirmed cleanup transcript (bad rc, missing GUID, or wrong GUID) logs 'may remain' and never logs success."""
        conn = self._base_conn(
            execute_ps_seq=[
                _make_ps_result(ds_stdout, rc=ds_rc),
                _make_ps_result("", rc=0),  # rmdir
            ]
        )
        with patch.object(module, "_upload", return_value=True):
            module._cleanup(mock_log, conn, GUID_NORM, DRIVE, True, STAGING)
        assert any("may remain" in str(c) for c in mock_log.fail.call_args_list)
        mock_log.debug.assert_not_called()

    # -- step independence --

    def test_ntds_del_failure_does_not_prevent_diskshadow(self, module, mock_log):
        conn = self._base_conn(
            execute_ps_seq=[
                Exception("del ntds failed"),  # del ntds raises (suppressed)
                _make_ps_result(VALID_CLEANUP_STDOUT),  # diskshadow cleanup
                _make_ps_result("", rc=0),  # rmdir
            ]
        )
        with patch.object(module, "_upload", return_value=True):
            module._cleanup(
                mock_log,
                conn,
                GUID_NORM,
                DRIVE,
                True,
                STAGING,
                ntds_path=f"{STAGING}\\ntds.dit",
            )
        assert conn.conn.execute_ps.call_count >= 2

    def test_diskshadow_failure_does_not_prevent_rmdir(self, module, mock_log):
        conn = self._base_conn(
            execute_ps_seq=[
                _make_ps_result("error", rc=1),  # diskshadow cleanup returns error
                _make_ps_result("", rc=0),  # rmdir
            ]
        )
        with patch.object(module, "_upload", return_value=True):
            module._cleanup(mock_log, conn, GUID_NORM, DRIVE, True, STAGING)
        calls = [str(c) for c in conn.conn.execute_ps.call_args_list]
        assert any("rmdir" in c for c in calls), (
            "rmdir must run even after diskshadow failure"
        )

    # -- GUID gating --

    def test_no_guid_skips_diskshadow_but_rmdir_still_runs(self, module, mock_log):
        conn = self._base_conn()
        with patch.object(module, "_upload", return_value=True) as mock_up:
            module._cleanup(mock_log, conn, None, DRIVE, False, STAGING)
        mock_up.assert_not_called()
        calls = [str(c) for c in conn.conn.execute_ps.call_args_list]
        assert any("rmdir" in c for c in calls)

    def test_no_delete_shadows_all_in_any_uploaded_script(self, module, mock_log):
        conn = self._base_conn()
        seen = []

        def capture(log, c, content, path):
            seen.append(content)
            return True

        with patch.object(module, "_upload", side_effect=capture):
            module._cleanup(mock_log, conn, GUID_NORM, DRIVE, True, STAGING)
        for script in seen:
            assert "delete shadows all" not in script.lower()

    def test_diskshadow_cleanup_exception_still_runs_rmdir(self, module, mock_log):
        """If DiskShadow execute raises during cleanup, rmdir must still run and GUID logged."""
        conn = self._base_conn(
            execute_ps_seq=[
                Exception("ps transport raised"),  # diskshadow cleanup raises (caught)
                _make_ps_result("", rc=0),  # rmdir
            ]
        )
        with patch.object(module, "_upload", return_value=True):
            module._cleanup(mock_log, conn, GUID_NORM, DRIVE, True, STAGING)
        calls = [str(c) for c in conn.conn.execute_ps.call_args_list]
        assert any("rmdir" in c for c in calls), (
            "rmdir must run even when DiskShadow raises"
        )
        assert any("may remain" in str(c) for c in mock_log.fail.call_args_list)

    def test_rmdir_failure_logs_staging_path(self, module, mock_log):
        """Non-zero rmdir rc must log the staging path; snapshot cleanup must still run independently."""
        conn = self._base_conn(
            execute_ps_seq=[
                _make_ps_result(
                    VALID_CLEANUP_STDOUT, rc=0
                ),  # diskshadow cleanup - confirmed
                _make_ps_result("", rc=1),  # rmdir returns non-zero
            ]
        )
        with patch.object(module, "_upload", return_value=True):
            module._cleanup(mock_log, conn, GUID_NORM, DRIVE, True, STAGING)
        fail_messages = [str(c.args[0]) for c in mock_log.fail.call_args_list]
        assert any(STAGING in m for m in fail_messages), (
            "staging path must appear in fail message"
        )
        # Snapshot cleanup succeeded independently before rmdir was attempted
        mock_log.debug.assert_any_call("Snapshot deleted successfully")

    def test_rmdir_exception_logs_staging_path(self, module, mock_log):
        """Transport exception from rmdir _run_cmd must log the staging path and exception text without propagating."""
        conn = self._base_conn(
            execute_ps_seq=[
                _make_ps_result(
                    VALID_CLEANUP_STDOUT, rc=0
                ),  # diskshadow cleanup - confirmed
                Exception("adapter failed"),  # rmdir raises
            ]
        )
        with patch.object(module, "_upload", return_value=True):
            module._cleanup(
                mock_log, conn, GUID_NORM, DRIVE, True, STAGING
            )  # must not raise
        fail_messages = [str(c.args[0]) for c in mock_log.fail.call_args_list]
        assert any(STAGING in m for m in fail_messages), (
            "staging path must appear in fail message"
        )
        assert any("adapter failed" in m for m in fail_messages), (
            "exception text must appear in fail message"
        )
        mock_log.debug.assert_any_call("Snapshot deleted successfully")


# ---------------------------------------------------------------------------
# TestOnLoginIntegration
# ---------------------------------------------------------------------------


class TestOnLoginIntegration:
    """End-to-end integration: all NetExec boundaries mocked.

    The execute_ps side-effect list covers the full happy-path sequence:
      [0] whoami /priv  (SeBackupPrivilege check via _run_cmd)
      [1] mkdir staging
      [2] diskshadow create
      [3] dir ntds.dit accessibility check
      [4] robocopy
      [5] reg save
      [6] remove ntds_dst  (inside _cleanup)
      [7] remove system_dst (inside _cleanup)
      [8] diskshadow cleanup
      [9] rmdir staging
    connection.execute (PS-native, no adapter) handles:
      [0] GetDrives
      [1] PS size query for ntds_dst
      [2] PS size query for system_dst
    Tests that abort early simply leave later items unconsumed.
    """

    def _make_conn(
        self,
        *,
        priv_out=PRIV_ENABLED,
        drives_out=DRIVES_CZ,
        ds_stdout=None,
        mkdir_rc=0,
        ds_rc=0,
        dir_rc=0,
        rob_rc=0,
        reg_rc=0,
        fetch_side=None,
        ps_size="1024\n",
    ):
        conn = MagicMock()
        conn.conn = MagicMock()

        # connection.execute is used only for PS-native operations:
        # GetDrives and (Get-Item ...).Length size queries.
        def execute_dispatch(*args, **kwargs):
            return execute_dispatch.responses.pop(0)

        execute_dispatch.responses = [
            drives_out,  # GetDrives
            ps_size,  # PS size query for ntds_dst
            ps_size,  # PS size query for system_dst
        ]
        conn.execute.side_effect = execute_dispatch

        # All native CMD commands go through _run_cmd -> execute_ps.
        conn.conn.execute_ps.side_effect = [
            _make_ps_result(priv_out),  # [0] whoami /priv
            _make_ps_result("", rc=mkdir_rc),  # [1] mkdir staging
            _make_ps_result(
                ds_stdout or VALID_DS_STDOUT, rc=ds_rc
            ),  # [2] diskshadow create
            _make_ps_result("", rc=dir_rc),  # [3] dir ntds.dit check
            _make_ps_result("", rc=rob_rc),  # [4] robocopy
            _make_ps_result("", rc=reg_rc),  # [5] reg save
            _make_ps_result("", rc=0),  # [6] del ntds (cleanup)
            _make_ps_result("", rc=0),  # [7] del system (cleanup)
            _make_ps_result(VALID_CLEANUP_STDOUT, rc=0),  # [8] diskshadow cleanup
            _make_ps_result("", rc=0),  # [9] rmdir staging
        ]

        size_bytes = int(ps_size.strip()) if ps_size else 64

        def fake_fetch(remote, local_p):
            with open(local_p, "wb") as f:
                f.write(b"x" * size_bytes)

        if fetch_side is not None:
            conn.conn.fetch.side_effect = fetch_side
        else:
            conn.conn.fetch.side_effect = fake_fetch

        conn.conn.copy = MagicMock()
        conn.output_file_template = "/tmp/nxc_{output_folder}/host"
        return conn

    # -- happy path --

    def test_full_success_prints_secretsdump_command(self, module, mock_log, tmp_path):
        conn = self._make_conn()
        conn.output_file_template = str(tmp_path / "{output_folder}" / "host")
        ctx = make_ctx(mock_log)
        with patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID):
            module.on_login(ctx, conn)
        mock_log.highlight.assert_called_once()
        assert "impacket-secretsdump" in mock_log.highlight.call_args[0][0]

    def test_no_native_command_uses_execute_cmd(self, module, mock_log, tmp_path):
        """The module must never call connection.conn.execute_cmd directly."""
        conn = self._make_conn()
        conn.output_file_template = str(tmp_path / "{output_folder}" / "host")
        ctx = make_ctx(mock_log)
        with patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID):
            module.on_login(ctx, conn)
        conn.conn.execute_cmd.assert_not_called()

    def test_robocopy_command_includes_reliability_flags(
        self, module, mock_log, tmp_path
    ):
        """/r:2 /w:1 /j must appear in the robocopy command issued via execute_ps."""
        conn = self._make_conn()
        conn.output_file_template = str(tmp_path / "{output_folder}" / "host")
        ctx = make_ctx(mock_log)
        with patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID):
            module.on_login(ctx, conn)
        all_ps_args = " ".join(str(c) for c in conn.conn.execute_ps.call_args_list)
        assert "/r:2" in all_ps_args
        assert "/w:1" in all_ps_args
        assert "/j" in all_ps_args

    # -- early-exit paths --

    def test_missing_privilege_returns_early(self, module, mock_log):
        """Only the priv-check execute_ps call must be made; no mkdir/diskshadow."""
        conn = self._make_conn(priv_out=PRIV_DISABLED)
        ctx = make_ctx(mock_log)
        with patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID):
            module.on_login(ctx, conn)
        # Only the priv check was executed via execute_ps
        assert conn.conn.execute_ps.call_count == 1
        mock_log.fail.assert_called()

    def test_mkdir_failure_returns_before_diskshadow(self, module, mock_log):
        conn = self._make_conn(mkdir_rc=1)
        ctx = make_ctx(mock_log)
        with patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID):
            module.on_login(ctx, conn)
        diskshadow_calls = [
            c for c in conn.conn.execute_ps.call_args_list if "diskshadow" in str(c)
        ]
        assert not diskshadow_calls
        mock_log.fail.assert_called()

    def test_no_drive_available_returns_early_without_snapshot(self, module, mock_log):
        conn = self._make_conn(
            drives_out="\n".join(
                f"{letter}:\\" for letter in "DCEFGHIJKLMNOPQRSTUVWXYZ"
            )
            + "\n"
        )
        ctx = make_ctx(mock_log)
        with patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID):
            module.on_login(ctx, conn)
        diskshadow_calls = [
            c for c in conn.conn.execute_ps.call_args_list if "diskshadow" in str(c)
        ]
        assert not diskshadow_calls
        mock_log.fail.assert_called()

    # -- GUID discovery failures --

    def test_no_guid_in_ds_output_calls_cleanup_with_none_guid(self, module, mock_log):
        conn = self._make_conn(ds_stdout="No snapshot information here.\r\n")
        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)
        mock_cleanup.assert_called_once()
        guid_arg = mock_cleanup.call_args[0][2]
        assert guid_arg is None, (
            "cleanup must be called with shadow_guid=None when GUID unknown"
        )
        mock_log.fail.assert_called()

    def test_ambiguous_guid_calls_cleanup_with_none_guid(self, module, mock_log):
        ambiguous = f"  -> %{ALIAS}% = {{{GUID}}}\r\n  -> %{ALIAS}% = {{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}}\r\n"
        conn = self._make_conn(ds_stdout=ambiguous)
        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)
        guid_arg = mock_cleanup.call_args[0][2]
        assert guid_arg is None
        mock_log.fail.assert_called()

    # -- exposure verification failures --

    def test_expose_confirmation_missing_calls_cleanup_with_guid(
        self, module, mock_log
    ):
        """GUID found but no exposure confirmation -> cleanup with verified GUID, expose_reported=False."""
        conn = self._make_conn(ds_stdout=DS_NO_EXPOSE)
        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)
        mock_cleanup.assert_called_once()
        guid_arg = mock_cleanup.call_args[0][2]
        expose_arg = mock_cleanup.call_args[0][4]
        assert guid_arg == GUID_NORM
        assert expose_arg is False
        mock_log.fail.assert_called()

    def test_ntds_path_inaccessible_calls_cleanup(self, module, mock_log):
        """Drive exposed but ntds.dit dir check fails -> cleanup with verified GUID, expose_reported=True."""
        conn = self._make_conn(dir_rc=2)
        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)
        mock_cleanup.assert_called_once()
        guid_arg = mock_cleanup.call_args[0][2]
        expose_arg = mock_cleanup.call_args[0][4]
        assert guid_arg == GUID_NORM
        assert expose_arg is True
        mock_log.fail.assert_called()

    # -- acquisition failures --

    def test_robocopy_failure_calls_cleanup_with_verified_guid(self, module, mock_log):
        conn = self._make_conn(rob_rc=8)
        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)
        guid_arg = mock_cleanup.call_args[0][2]
        assert guid_arg == GUID_NORM, (
            "cleanup must receive verified GUID even after robocopy failure"
        )
        mock_log.fail.assert_called()

    def test_robocopy_rc_7_is_successful(self, module, mock_log, tmp_path):
        """Robocopy exit codes 0-7 are all success variants; rc=7 must not abort."""
        conn = self._make_conn(rob_rc=7)
        conn.output_file_template = str(tmp_path / "{output_folder}" / "host")
        ctx = make_ctx(mock_log)
        with patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID):
            module.on_login(ctx, conn)
        mock_log.highlight.assert_called_once()
        assert "impacket-secretsdump" in mock_log.highlight.call_args[0][0]

    def test_reg_save_failure_calls_cleanup_with_verified_guid(self, module, mock_log):
        conn = self._make_conn(reg_rc=1)
        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)
        guid_arg = mock_cleanup.call_args[0][2]
        assert guid_arg == GUID_NORM
        mock_log.fail.assert_called()

    # -- download and size verification paths --

    def test_size_mismatch_on_ntds_logs_fail_and_cleanup_still_runs(
        self, module, mock_log, tmp_path
    ):
        ntds_dir = tmp_path / "ntds"
        ntds_dir.mkdir(parents=True)
        conn = self._make_conn(ps_size="999\n")
        conn.output_file_template = str(tmp_path / "{output_folder}" / "host")

        # Fetch writes 512 bytes but remote says 999 -> mismatch
        def small_fetch(remote, local_p):
            with open(local_p, "wb") as f:
                f.write(b"x" * 512)

        conn.conn.fetch.side_effect = small_fetch

        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)
        mock_log.fail.assert_called()
        mock_cleanup.assert_called_once()

    def test_fetch_exception_cleanup_still_runs(self, module, mock_log, tmp_path):
        """A fetch exception must not prevent cleanup from running."""
        conn = self._make_conn(
            fetch_side=[Exception("network reset"), Exception("network reset")]
        )
        conn.output_file_template = str(tmp_path / "{output_folder}" / "host")
        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
            patch("os.makedirs"),
        ):
            module.on_login(ctx, conn)
        mock_cleanup.assert_called_once()
        mock_log.fail.assert_called()

    # -- secretsdump command quoting --

    def test_secretsdump_command_quotes_paths_with_spaces(
        self, module, mock_log, tmp_path
    ):
        spacedir = tmp_path / "path with spaces"
        conn = self._make_conn()
        conn.output_file_template = str(spacedir / "{output_folder}" / "host")
        ctx = make_ctx(mock_log)
        with patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID):
            module.on_login(ctx, conn)
        cmd = mock_log.highlight.call_args[0][0]
        assert "impacket-secretsdump" in cmd
        # shlex.quote wraps paths containing spaces in single quotes
        assert "'" in cmd, "paths with spaces must be quoted in secretsdump command"

    # -- exception-safety and rc-capture --

    def test_exception_after_guid_is_logged_and_does_not_escape(self, module, mock_log):
        """Unexpected exception after GUID confirmed: logged via log.fail, cleanup called once, does not escape."""
        conn = MagicMock()
        conn.conn = MagicMock()

        def execute_dispatch(*args, **kwargs):
            return execute_dispatch.responses.pop(0)

        execute_dispatch.responses = [DRIVES_CZ]
        conn.execute.side_effect = execute_dispatch

        conn.conn.execute_ps.side_effect = [
            _make_ps_result(PRIV_ENABLED),  # [0] priv check
            _make_ps_result("", rc=0),  # [1] mkdir
            _make_ps_result(VALID_DS_STDOUT),  # [2] diskshadow create
            _make_ps_result("", rc=0),  # [3] dir check
            Exception("connection lost"),  # [4] robocopy raises unexpectedly
        ]
        conn.conn.copy = MagicMock()
        conn.output_file_template = "/tmp/nxc_{output_folder}/host"

        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)  # must NOT raise

        mock_cleanup.assert_called_once()
        guid_arg = mock_cleanup.call_args[0][2]
        assert guid_arg == GUID_NORM, (
            "cleanup must receive the confirmed GUID even after exception"
        )
        fail_messages = [str(c) for c in mock_log.fail.call_args_list]
        assert any("connection lost" in m for m in fail_messages), (
            "acquisition exception cause must be logged via log.fail before cleanup runs"
        )

    def test_acquisition_error_logged_when_cleanup_also_fails(self, module, mock_log):
        """Acquisition error is logged before finally runs even when _cleanup itself raises."""
        conn = MagicMock()
        conn.conn = MagicMock()

        def execute_dispatch(*args, **kwargs):
            return execute_dispatch.responses.pop(0)

        execute_dispatch.responses = [DRIVES_CZ]
        conn.execute.side_effect = execute_dispatch

        conn.conn.execute_ps.side_effect = [
            _make_ps_result(PRIV_ENABLED),  # [0] priv check
            _make_ps_result("", rc=0),  # [1] mkdir
            _make_ps_result(VALID_DS_STDOUT),  # [2] diskshadow create
            _make_ps_result("", rc=0),  # [3] dir check
            Exception("connection lost"),  # [4] robocopy raises (acquisition error)
        ]
        conn.conn.copy = MagicMock()
        conn.output_file_template = "/tmp/nxc_{output_folder}/host"

        ctx = make_ctx(mock_log)

        def cleanup_that_raises(*args, **kwargs):
            raise RuntimeError("cleanup transport failed")

        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup", side_effect=cleanup_that_raises),
        ):
            module.on_login(ctx, conn)  # must NOT raise despite cleanup also failing

        fail_messages = [str(c) for c in mock_log.fail.call_args_list]
        # Acquisition error must be logged before cleanup runs, so "connection lost" always appears.
        assert any("connection lost" in m for m in fail_messages), (
            "acquisition error must be logged even when cleanup raises"
        )

    def test_nonzero_diskshadow_rc_calls_cleanup_with_guid(self, module, mock_log):
        """Non-zero DiskShadow rc: GUID still parsed, cleanup called with it, fail logged."""
        conn = self._make_conn(ds_rc=1)
        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)

        mock_cleanup.assert_called_once()
        guid_arg = mock_cleanup.call_args[0][2]
        expose_arg = mock_cleanup.call_args[0][4]
        # GUID was present in VALID_DS_STDOUT, so it should be recovered
        assert guid_arg == GUID_NORM
        # DiskShadow failed before exposure was confirmed
        assert expose_arg is False
        assert mock_log.fail.called

    def test_nonzero_diskshadow_rc_surfaces_output_and_cleans_up_guid(
        self, module, mock_log
    ):
        """Non-zero DiskShadow rc must log stdout/stderr content and clean up the parsed GUID."""
        ds_fail_stdout = f"DISKSHADOW> create\r\n  -> %{ALIAS}% = {{{GUID}}}\r\nError: volume not found\r\n"
        ds_fail_stderr = "diskshadow: access denied"
        conn = self._make_conn(
            ds_stdout=ds_fail_stdout,
            ds_rc=3,
        )
        # Inject the stderr via a custom execute_ps sequence for the diskshadow slot
        conn.conn.execute_ps.side_effect = None
        conn.conn.execute_ps.return_value = None

        def execute_dispatch(*args, **kwargs):
            return execute_dispatch.responses.pop(0)

        execute_dispatch.responses = [DRIVES_CZ]
        conn.execute.side_effect = execute_dispatch

        conn.conn.execute_ps.side_effect = [
            _make_ps_result(PRIV_ENABLED),  # priv check
            _make_ps_result("", rc=0),  # mkdir
            _make_ps_result(ds_fail_stdout, ds_fail_stderr, rc=3),  # diskshadow create
        ]

        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)

        # Failure message emitted
        fail_messages = [str(c) for c in mock_log.fail.call_args_list]
        assert any("code 3" in m for m in fail_messages), (
            "exit code must appear in fail message"
        )

        # stdout content surfaced via display
        display_messages = " ".join(str(c) for c in mock_log.display.call_args_list)
        assert "volume not found" in display_messages, (
            "DiskShadow stdout must be surfaced"
        )

        # stderr content surfaced via fail
        assert any("access denied" in m for m in fail_messages), (
            "DiskShadow stderr must be surfaced"
        )

        # GUID was parseable from stdout; cleanup must use it
        mock_cleanup.assert_called_once()
        guid_arg = mock_cleanup.call_args[0][2]
        assert guid_arg == GUID_NORM, (
            "exact GUID must be passed to cleanup even on non-zero rc"
        )
        expose_arg = mock_cleanup.call_args[0][4]
        assert expose_arg is False

    def test_nonzero_rc_with_envvar_line_cleans_up_exact_guid(self, module, mock_log):
        """Non-zero rc with the real env-var line in stdout must clean the exact GUID with expose_reported=False."""
        # Build stdout that has only the env-var format GUID (no %alias% = {GUID} line)
        envvar_only_stdout = (
            f"DISKSHADOW> create\r\n"
            f"Alias {ALIAS} for shadow ID {{{GUID}}} set as environment variable.\r\n"
        )
        conn = self._make_conn(ds_stdout=envvar_only_stdout, ds_rc=3)
        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)

        mock_cleanup.assert_called_once()
        guid_arg = mock_cleanup.call_args[0][2]
        expose_arg = mock_cleanup.call_args[0][4]
        assert guid_arg == GUID_NORM, "exact GUID from env-var line must reach cleanup"
        assert expose_arg is False

    def test_nonzero_rc_without_alias_bound_guid_skips_diskshadow_cleanup(
        self, module, mock_log
    ):
        """Non-zero rc with no alias-bound GUID in stdout must not run DiskShadow cleanup."""
        no_guid_stdout = "DISKSHADOW> create\r\nError: volume not found\r\n"
        conn = self._make_conn(ds_stdout=no_guid_stdout, ds_rc=3)
        ctx = make_ctx(mock_log)
        with (
            patch("nxc.modules.ntds_shadow.gen_random_string", return_value=RUN_ID),
            patch.object(module, "_cleanup") as mock_cleanup,
        ):
            module.on_login(ctx, conn)

        mock_cleanup.assert_called_once()
        guid_arg = mock_cleanup.call_args[0][2]
        assert guid_arg is None, (
            "cleanup must be called with None when no alias-bound GUID found"
        )
        # A warning about the possible remaining snapshot must be logged
        fail_messages = [str(c) for c in mock_log.fail.call_args_list]
        assert any("snapshot may remain" in m for m in fail_messages)
