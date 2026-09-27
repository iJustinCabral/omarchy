"""Copy an externally reviewed source inventory to the fixed private runtime.

This module never imports or executes the source tree, installs a service, issues
qualification, copies UKIs/unlock assets or performs host power operations.
Source may be user-owned: externally reviewed exact byte hashes are the boundary.
Only the root-owned, verified snapshot is suitable for privileged execution.
Partial deployment remains preserved and refuses retry; no overwrite/update API.
"""

import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


STATE = Path("/var/lib/omarchy/t2-hibernate-product")
RUNTIME = STATE / "runtime"
REVIEW = STATE / "runtime-deployment-review.json"
SCHEMA = "omarchy-t2-product-runtime-snapshot-v1"
TREES = ("packages/t2-suspend/hibernate", "packages/t2-suspend/experiments")
ENTRYPOINT = TREES[0] + "/product.py"
MANIFEST = "snapshot.json"
PENDING = ".runtime-pending"
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
CHUNK = 1024 * 1024


def _encoded(value):
  return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _source_name(name):
  path = PurePosixPath(name)
  if path.is_absolute() or ".." in path.parts or str(path) != name or not any(name.startswith(tree + "/") for tree in TREES):
    raise ValueError("Runtime source path outside fixed code trees")
  if any(part.startswith(".") for part in path.parts): raise ValueError("Hidden runtime source path")
  allowed = path.suffix in (".py", ".md", ".c", ".conf", ".patch", ".service", ".sh")
  allowed |= path.name in ("Makefile", "Kbuild", "functions")
  allowed |= not path.suffix and (path.parent.name in ("hooks", "install") or path.name.startswith(("run-", "omarchy-")))
  if not allowed: raise ValueError("Non-source asset cannot enter runtime snapshot")


def _open_directory(path):
  path = Path(path)
  if not path.is_absolute() or ".." in path.parts: raise ValueError("Explicit absolute deployment path required")
  fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
  try:
    for part in path.parts[1:]:
      child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
      os.close(fd)
      fd = child
    return fd
  except BaseException:
    os.close(fd)
    raise


def _private(fd, directory=False):
  info = os.fstat(fd)
  expected = stat.S_ISDIR if directory else stat.S_ISREG
  if not expected(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
    raise ValueError("Runtime destination/review must be current-owner private")
  if not directory and info.st_nlink != 1: raise ValueError("Runtime file has multiple links")


def _source_fd(source, name):
  _source_name(name)
  fd = _open_directory(Path(source) / Path(name).parent)
  try:
    child = os.open(Path(name).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
  finally:
    os.close(fd)
  info = os.fstat(child)
  if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= MAX_FILE:
    os.close(child)
    raise ValueError("Runtime source must be bounded regular non-linked bytes")
  return child


def _identity(fd):
  size, digest = 0, hashlib.sha256()
  while True:
    raw = os.read(fd, CHUNK)
    if not raw: break
    size += len(raw)
    if size > MAX_FILE: raise ValueError("Runtime source exceeds byte limit")
    digest.update(raw)
  return {"size": size, "sha256": digest.hexdigest()}


def inventory(source_directory):
  """Read-only exact source inventory; this is NOT approval or qualification."""
  source = Path(source_directory)
  descriptor = _open_directory(source)
  os.close(descriptor)
  files = {}
  for tree in TREES:
    start = source / tree
    descriptor = _open_directory(start)
    os.close(descriptor)
    for directory, folders, names in os.walk(start, followlinks=False):
      for name in folders:
        if (Path(directory) / name).is_symlink(): raise ValueError("Symlinked runtime source directory")
      folders[:] = [name for name in folders if name != "__pycache__"]
      for name in sorted(names):
        if name == ".gitattributes": continue
        relative = (Path(directory) / name).relative_to(source).as_posix()
        fd = _source_fd(source, relative)
        try: files[relative] = _identity(fd)
        finally: os.close(fd)
  if ENTRYPOINT not in files: raise ValueError("Missing routine dispatcher")
  if sum(value["size"] for value in files.values()) > MAX_TOTAL: raise ValueError("Runtime source inventory exceeds limit")
  return dict(sorted(files.items()))


def _verify_tree(directory, expected):
  actual = inventory(directory)
  if actual != expected: raise ValueError("Runtime snapshot byte inventory differs")
  for current, folders, names in os.walk(directory, followlinks=False):
    fd = _open_directory(current)
    try: _private(fd, directory=True)
    finally: os.close(fd)
    for name in names:
      fd = os.open(Path(current) / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
      try: _private(fd)
      finally: os.close(fd)


def deploy_snapshot(source_directory, *, root):
  """Copy reviewed bytes exclusively; explicit root maps only fixed destinations.

  Live root `/` requires root identity. Other roots are synthetic test fixtures.
  The fixed root-private REVIEW is authored externally, never by this helper.
  Publication is after file/directory fsync and exact private readback only.
  """
  root = Path(root)
  if not root.is_absolute(): raise ValueError("Explicit absolute deployment root required")
  if root == Path("/") and os.geteuid() != 0: raise ValueError("Explicit root deployment required")
  state = root / STATE.relative_to("/")
  parent = _open_directory(state)
  lock = None
  try:
    _private(parent, directory=True)
    lock = os.open("runtime-deployment.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    _private(lock)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if any(name in os.listdir(parent) for name in ("runtime", PENDING)):
      raise ValueError("Existing or partial runtime snapshot refuses overwrite")
    fd = os.open(REVIEW.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
      _private(fd)
      raw = os.read(fd, MAX_FILE + 1)
      if len(raw) > MAX_FILE: raise ValueError("Runtime review exceeds limit")
    finally: os.close(fd)
    def unique(pairs):
      value = {}
      for key, item in pairs:
        if key in value: raise ValueError("Duplicate runtime review field")
        value[key] = item
      return value
    review = json.loads(raw, object_pairs_hook=unique)
    if type(review) is not dict or set(review) != {"protocol", "approved", "reviewed_commit", "files"}:
      raise ValueError("Runtime review fields differ")
    if review["protocol"] != SCHEMA or review["approved"] is not True or type(review["reviewed_commit"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", review["reviewed_commit"]):
      raise ValueError("Explicit reviewed source approval required")
    expected = inventory(source_directory)
    if review["files"] != expected: raise ValueError("Source bytes differ from independently reviewed inventory")
    os.mkdir(PENDING, mode=0o700, dir_fd=parent)
    os.fsync(parent)
    staging = state / PENDING
    for name, identity in expected.items():
      target = staging / name
      target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
      # pathlib's intermediate parents use default mode; normalize every new
      # directory under this exclusive private staging tree before publication.
      for directory in (target.parent, *target.parent.parents):
        if directory == state: break
        directory.chmod(0o700)
      src = _source_fd(source_directory, name)
      out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
      try:
        size, digest = 0, hashlib.sha256()
        while True:
          chunk = os.read(src, CHUNK)
          if not chunk: break
          size += len(chunk)
          if size > MAX_FILE: raise ValueError("Source changed beyond bounded size")
          digest.update(chunk)
          view = memoryview(chunk)
          while view:
            written = os.write(out, view)
            if written <= 0: raise OSError("Short runtime snapshot write")
            view = view[written:]
        if {"size": size, "sha256": digest.hexdigest()} != identity: raise ValueError("Source changed while copying approved bytes")
        os.fchmod(out, 0o600)
        os.fsync(out)
      finally:
        os.close(src)
        os.close(out)
    _verify_tree(staging, expected)
    completion = {"protocol": SCHEMA, "reviewed_commit": review["reviewed_commit"], "review_sha256": hashlib.sha256(raw).hexdigest(),
                  "files": expected, "entrypoint": ENTRYPOINT}
    fd = os.open(staging / MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
      stream.write(_encoded(completion))
      stream.flush()
      os.fchmod(stream.fileno(), 0o600)
      os.fsync(stream.fileno())
    if (staging / MANIFEST).read_bytes() != _encoded(completion):
      raise ValueError("Runtime completion readback differs")
    for directory, folders, names in os.walk(staging, topdown=False):
      fd = _open_directory(directory)
      try: os.fsync(fd)
      finally: os.close(fd)
    os.rename(PENDING, "runtime", src_dir_fd=parent, dst_dir_fd=parent)
    os.fsync(parent)
    _verify_tree(state / "runtime", expected)
    return completion
  finally:
    if lock is not None: os.close(lock)
    os.close(parent)
