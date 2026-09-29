"""Bounded desktop admission using logind identity and actual shell security.

Only the fixed live root may use native commands. Fixture injection never
reaches live operations. Desktop IPC executes after dropping to the discovered
session user, including when the Omarchy checkout is user writable.
"""
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
import time


LIMIT = 65536
PROPERTIES = ("Id", "User", "Leader", "Seat", "Active", "Remote", "Type", "Class", "State", "TimestampMonotonic")


def _pairs(values):
  result = {}
  for key, value in values:
    if key in result: raise ValueError("Duplicate desktop status field")
    result[key] = value
  return result


def _native(argv, env, uid, gid):
  options = {} if uid is None else {"user": uid, "group": gid, "extra_groups": (), "umask": 0o077}
  # A malicious/unavailable IPC peer cannot fill Python's memory or wait forever.
  with tempfile.TemporaryFile() as output:
    result = subprocess.run(argv, env=env, stdout=output, stderr=subprocess.DEVNULL,
                            timeout=2, check=False, **options)
    output.seek(0)
    raw = output.read(LIMIT + 1)
  if result.returncode != 0 or len(raw) > LIMIT:
    raise ValueError("Unavailable bounded desktop query")
  return raw.decode("utf-8", errors="strict")


class Gate:
  def __init__(self, root, *, command_runner=None):
    self.root = Path(root)
    self.deadline = float("inf")
    if not self.root.is_absolute() or self.root.resolve() != self.root or not self.root.is_dir():
      raise ValueError("Explicit canonical desktop root required")
    if self.root == Path("/"):
      if os.geteuid() != 0 or command_runner is not None:
        raise ValueError("Fixed root desktop gate required; no injected live commands")
      self.command = _native
    else:
      if command_runner is None: raise ValueError("Fixture desktop gate requires explicit commands")
      self.command = command_runner

  def _query(self, argv, *, env=None, uid=None, gid=None):
    if time.monotonic() >= self.deadline: raise TimeoutError("Desktop gate deadline expired")
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"} if env is None else env
    value = self.command(tuple(argv), environment, uid, gid)
    if time.monotonic() >= self.deadline: raise TimeoutError("Desktop gate deadline expired")
    if type(value) is not str or len(value.encode()) > LIMIT:
      raise ValueError("Unavailable bounded desktop query")
    return value.strip()

  def _read(self, relative):
    with (self.root / relative).open("rb") as source: raw = source.read(LIMIT + 1)
    if len(raw) > LIMIT: raise ValueError("Oversized desktop identity")
    return raw.decode("utf-8", errors="strict")

  def discover(self):
    sessions = self._query(("/usr/bin/loginctl", "list-sessions", "--no-legend", "--no-pager")).splitlines()
    if len(sessions) > 64: raise ValueError("Oversized session inventory")
    graphical = []
    for row in sessions:
      session_id = row.split()[0]
      if not re.fullmatch(r"[A-Za-z0-9]+", session_id): raise ValueError("Malformed logind session")
      raw = self._query(("/usr/bin/loginctl", "show-session", session_id, "--no-pager",
                         *("--property=" + item for item in PROPERTIES)))
      values = dict(line.split("=", 1) for line in raw.splitlines())
      if set(values) != set(PROPERTIES) or values["Id"] != session_id:
        raise ValueError("Incomplete logind session")
      if values["Class"] == "user" and values["Type"] in ("wayland", "x11") and values["Remote"] == "no":
        graphical.append(values)
    # A second local graphical session makes the per-user desktop bus ambiguous.
    if len(graphical) != 1: raise ValueError("Exactly one local graphical session required")
    values = graphical[0]
    if values["Type"] != "wayland" or values["Active"] != "yes" or values["State"] != "active" or not values["Seat"]:
      raise ValueError("Active local Wayland seat required")
    for key in ("User", "Leader", "TimestampMonotonic"):
      if not values[key].isdigit() or int(values[key]) <= 0: raise ValueError("Invalid logind session identity")
    uid, leader = int(values["User"]), int(values["Leader"])
    status = self._read("proc/" + str(leader) + "/status")
    uids = [line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")]
    # Display managers may retain a root-owned login helper as session leader.
    # Logind's User identifies the IPC user; leader credentials bind continuity.
    if len(uids) != 1 or len(uids[0]) != 4 or any(not item.isdigit() for item in uids[0]):
      raise ValueError("Missing logind leader credentials")
    process = self._read("proc/" + str(leader) + "/stat")
    fields = process[process.rfind(")") + 2:].split()
    if len(fields) < 20 or not fields[19].isdigit(): raise ValueError("Missing leader start identity")
    return {**values, "leader_start": fields[19], "leader_uids": tuple(uids[0])}

  def require_secure(self, binding=None):
    self.deadline = time.monotonic() + 8
    current = self.discover()
    if binding is not None and current != binding: raise ValueError("Graphical session changed before power")
    uid = int(current["User"])
    account = pwd.getpwuid(uid)
    runtime = "/run/user/" + str(uid)
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "HOME": account.pw_dir,
                   "USER": account.pw_name, "LOGNAME": account.pw_name, "XDG_RUNTIME_DIR": runtime,
                   "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + runtime + "/bus"}
    raw = self._query(("/usr/bin/systemctl", "--user", "show-environment"), env=environment, uid=uid, gid=account.pw_gid)
    user_environment = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if user_environment.get("XDG_SESSION_ID") != current["Id"] or user_environment.get("XDG_RUNTIME_DIR") != runtime:
      raise ValueError("Desktop environment is not bound to the active session")
    display, omarchy = user_environment.get("WAYLAND_DISPLAY", ""), user_environment.get("OMARCHY_PATH", "")
    if not re.fullmatch(r"wayland-[0-9]+", display) or not Path(omarchy).is_absolute() or ".." in Path(omarchy).parts:
      raise ValueError("Missing exact desktop IPC environment")
    socket = (self.root / runtime.lstrip("/") / display).lstat()
    if not stat.S_ISSOCK(socket.st_mode) or socket.st_uid != uid:
      raise ValueError("Active user's Wayland socket required")
    environment.update({"XDG_SESSION_ID": current["Id"], "WAYLAND_DISPLAY": display,
                        "OMARCHY_PATH": omarchy, "OMARCHY_SHELL_IPC_TIMEOUT": "0.5s"})
    status = json.loads(self._query(("/usr/bin/bash", omarchy + "/bin/omarchy-shell", "lock", "status"),
                                    env=environment, uid=uid, gid=account.pw_gid), object_pairs_hook=_pairs,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite desktop status")))
    if type(status) is not dict or status.get("secure") is not True:
      raise ValueError("Desktop shell lock is not secure")
    if self.discover() != current: raise ValueError("Graphical session changed during secure check")
    return current

  def require_same_session(self, binding):
    """Root-only continuity check while the already secure user.slice is frozen."""
    self.deadline = time.monotonic() + 8
    if self.discover() != binding: raise ValueError("Graphical session changed before image write")
