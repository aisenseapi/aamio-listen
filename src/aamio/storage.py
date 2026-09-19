"""What this runtime keeps on the machine, who can read it, and for how long.

The service forgets a thread when it expires. This runtime does not: it keeps a
key, the read keys of open threads, an outbox, and, unless told otherwise, an
archive of decrypted messages. "Ephemeral" is about the network, and an outside
assessment on 18 September 2026 pointed out how easily it is read as a promise
about the whole system, and that mode 600 says little on Windows, where
inherited ACLs decide who reads a file.

So three things live here. Every file is opened private from its first byte.
A check says who can in fact read the home, by mode bits where those mean
something and by the access control list where they do not. And the archive is
a choice with a lifetime: keep, off, or so many days, with a ceiling on size.
"""

import json
import os
import subprocess
import sys
import time

ARCHIVE_MODES = ("keep", "off", "days")
DEFAULT_POLICY = {"mode": "keep", "days": None, "max_mb": None}

# Who may have access to a private folder on Windows without it being a finding:
# the system itself, the administrators of the machine, and whoever created or
# owns the file. Everything else is somebody else.
WINDOWS_EXPECTED = {"S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-4"}
WINDOWS_NAMES = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-4": "Interactive",
}


def is_windows():
    return os.name == "nt"


def make_private_dir(path):
    """The folder, for this user only where mode bits mean that."""
    os.makedirs(path, mode=0o700, exist_ok=True)

    if not is_windows():
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def open_private(path, append=False):
    """A file nobody else can read, from its first byte.

    Made 600 after it was written, a file was readable by anyone for a moment.
    """
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    handle = os.fdopen(os.open(path, flags, 0o600), "a" if append else "w", encoding="utf-8")

    if not is_windows():
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    return handle


def sync_dir(path):
    """After a rename: the new name is on disk only when the folder is.

    Windows has no such call for a folder, and the rename there is already
    journalled, so this does nothing on it.
    """
    if is_windows():
        return

    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return

    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def tighten(home):
    """Files an older version wrote with the default mode are made private. Returns what it changed."""
    changed = []

    if is_windows():
        return changed

    for folder, _, names in os.walk(home):
        for name in [None] + names:
            path = folder if name is None else os.path.join(folder, name)

            try:
                mode = os.stat(path).st_mode & 0o777
                wanted = 0o700 if name is None else 0o600

                if mode & 0o077:
                    os.chmod(path, wanted)
                    changed.append(path)
            except OSError:
                continue

    return changed


# ------------------------------------------------------- who can read it --


def windows_acl_findings(lines, me):
    """Findings from `sid|rights|type` lines, one per access rule. me is the current user's SID."""
    findings = []

    for line in lines:
        parts = [part.strip() for part in line.strip().split("|")]

        if len(parts) != 3 or parts[0] == "" or parts[2].lower() != "allow":
            continue

        sid, rights = parts[0], parts[1]

        if sid == me or sid in WINDOWS_EXPECTED:
            continue

        findings.append({
            "who": WINDOWS_NAMES.get(sid, sid),
            "rights": rights,
            "problem": "%s has access to this folder (%s), so the key and everything else in it can be read by others on this machine" % (WINDOWS_NAMES.get(sid, sid), rights),
        })

    return findings


def _windows_rules(path):
    quoted = path.replace("'", "''")
    script = (
        "$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; 'me|' + $me; "
        "(Get-Acl -LiteralPath '%s').Access | ForEach-Object { "
        "$sid = try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $_.IdentityReference.Value }; "
        "'{0}|{1}|{2}' -f $sid, $_.FileSystemRights, $_.AccessControlType }" % quoted
    )
    run = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=30)

    if run.returncode != 0:
        raise OSError((run.stderr or run.stdout or "powershell failed").strip()[:200])

    lines = [line for line in run.stdout.splitlines() if line.strip()]
    me = next((line.split("|", 1)[1].strip() for line in lines if line.startswith("me|")), "")

    return me, [line for line in lines if not line.startswith("me|")]


def check(home):
    """Who can read the home, as far as this platform lets us find out.

    private is True, False, or None when it could not be checked, and a None is
    never reported as a yes.
    """
    result = {"home": home, "private": None, "how": None, "findings": []}

    if not os.path.isdir(home):
        result["how"] = "not checked: there is no such folder yet"
        return result

    if is_windows():
        result["how"] = "the folder's access control list, read with Get-Acl. Mode bits say nothing on Windows."

        try:
            me, rules = _windows_rules(home)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            result["how"] = "not checked: the access control list could not be read (%s)" % error.__class__.__name__
            result["fix"] = "Run `icacls \"%s\"` and see that only you, SYSTEM and Administrators are listed." % home
            return result

        result["findings"] = windows_acl_findings(rules, me)
        result["private"] = not result["findings"]

        if result["findings"]:
            result["fix"] = "Remove the inherited access and keep your own: icacls \"%s\" /inheritance:r /grant:r \"%%USERNAME%%\":(OI)(CI)F" % home

        return result

    result["how"] = "owner and mode bits of the folder and every file in it"

    for folder, _, names in os.walk(home):
        for name in [None] + names:
            path = folder if name is None else os.path.join(folder, name)

            try:
                found = os.stat(path)
            except OSError:
                continue

            if hasattr(os, "getuid") and found.st_uid != os.getuid():
                result["findings"].append({"path": path, "problem": "owned by another user (uid %d)" % found.st_uid})
            elif found.st_mode & 0o077:
                result["findings"].append({"path": path, "problem": "readable by others (mode %o)" % (found.st_mode & 0o777)})

    result["private"] = not result["findings"]

    if result["findings"]:
        result["fix"] = "chmod -R go-rwx \"%s\"" % home

    return result


# ------------------------------------------------------------ the archive --


def read_policy(home):
    """The archive policy of this home. No file means keep, which is what every version did."""
    try:
        with open(os.path.join(home, "config.json"), encoding="utf-8") as handle:
            stored = json.load(handle).get("archive")
    except (OSError, ValueError, AttributeError):
        stored = None

    policy = dict(DEFAULT_POLICY)

    if isinstance(stored, dict) and stored.get("mode") in ARCHIVE_MODES:
        policy["mode"] = stored["mode"]

        if isinstance(stored.get("days"), int) and stored["days"] > 0:
            policy["days"] = stored["days"]

        if isinstance(stored.get("max_mb"), (int, float)) and stored["max_mb"] > 0:
            policy["max_mb"] = stored["max_mb"]

    if policy["mode"] == "days" and not policy["days"]:
        policy["mode"] = "keep"

    return policy


def parse_policy(text, max_mb=None):
    """keep, off or days:N, as typed on the command line."""
    text = (text or "").strip().lower()
    policy = dict(DEFAULT_POLICY)

    if text in ("keep", "off"):
        policy["mode"] = text
    elif text.startswith("days:") and text[5:].isdigit() and int(text[5:]) > 0:
        policy.update(mode="days", days=int(text[5:]))
    else:
        raise ValueError("the archive is keep, off or days:N with N a whole number of days, not %r" % text)

    if max_mb is not None:
        if max_mb <= 0:
            raise ValueError("--max-mb is a size above zero")

        policy["max_mb"] = max_mb

    return policy


def describe(policy):
    """One sentence a person or a model can act on."""
    size = " and never more than %s MB, oldest first out" % policy["max_mb"] if policy.get("max_mb") else ""

    if policy["mode"] == "off":
        return "Nothing decrypted is written to this machine. The key, the read keys of open threads and the outbox with sealed bytes still are, since the runtime cannot work without them."

    if policy["mode"] == "days":
        return "Decrypted messages and receipts are kept in archive/ for %d days%s, then removed. The service itself keeps nothing past a thread's expiry: this archive is yours, on this machine." % (policy["days"], size)

    return "Decrypted messages and receipts are kept in archive/ until you remove them%s. The service itself keeps nothing past a thread's expiry: this archive is yours, on this machine. `aamio archive days:30` gives it a lifetime, `aamio archive off` stops it." % size


def _records(path):
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue

            try:
                at = json.loads(line).get("at")
            except (ValueError, AttributeError):
                at = None

            yield (float(at) if isinstance(at, (int, float)) else None), line if line.endswith("\n") else line + "\n"


def prune(home, policy, now=None, everything=False):
    """Removes what the policy no longer keeps. Returns how many records went, and how many bytes are left.

    A record this cannot date is kept: what cannot be told old is not thrown
    away as old. Each file is rewritten beside itself and renamed over, so a
    crash in the middle leaves the old file whole.
    """
    folder = os.path.join(home, "archive")
    now = time.time() if now is None else now
    removed = 0

    if not os.path.isdir(folder):
        return {"removed": 0, "bytes": 0}

    names = sorted(name for name in os.listdir(folder) if name.endswith(".jsonl"))

    if everything:
        for name in names:
            removed += sum(1 for _ in _records(os.path.join(folder, name)))
            os.remove(os.path.join(folder, name))

        sync_dir(folder)
        return {"removed": removed, "bytes": 0}

    kept = {}
    horizon = now - policy["days"] * 86400 if policy.get("mode") == "days" and policy.get("days") else None

    for name in names:
        kept[name] = []

        for at, line in _records(os.path.join(folder, name)):
            if horizon is not None and at is not None and at < horizon:
                removed += 1
            else:
                kept[name].append((at, line))

    ceiling = int(policy["max_mb"] * 1024 * 1024) if policy.get("max_mb") else None

    if ceiling is not None:
        total = sum(len(line.encode("utf-8")) for records in kept.values() for _, line in records)
        oldest_first = sorted(((at if at is not None else now, name, index) for name, records in kept.items() for index, (at, _) in enumerate(records)))
        gone = set()

        for at, name, index in oldest_first:
            if total <= ceiling:
                break

            total -= len(kept[name][index][1].encode("utf-8"))
            gone.add((name, index))
            removed += 1

        for name in kept:
            kept[name] = [record for index, record in enumerate(kept[name]) if (name, index) not in gone]

    left = 0

    for name, records in kept.items():
        path = os.path.join(folder, name)
        text = "".join(line for _, line in records)
        left += len(text.encode("utf-8"))

        if removed == 0:
            continue

        with open_private(path + ".tmp") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(path + ".tmp", path)

    if removed:
        sync_dir(folder)

    return {"removed": removed, "bytes": left}


def status(home, policy):
    folder = os.path.join(home, "archive")
    files, size, oldest = 0, 0, None

    if os.path.isdir(folder):
        for name in os.listdir(folder):
            if not name.endswith(".jsonl"):
                continue

            files += 1
            size += os.path.getsize(os.path.join(folder, name))

            for at, _ in _records(os.path.join(folder, name)):
                if at is not None and (oldest is None or at < oldest):
                    oldest = at

    return {"policy": policy, "means": describe(policy), "files": files, "bytes": size, "oldest_at": None if oldest is None else int(oldest)}


def leftovers(home):
    """Temporary files an interrupted write left behind. The file they were to replace is whole."""
    found = []

    for folder, _, names in os.walk(home):
        found.extend(os.path.join(folder, name) for name in names if name.endswith(".tmp"))

    return found


if __name__ == "__main__":
    print(json.dumps(check(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/.aamio")), indent=2))
