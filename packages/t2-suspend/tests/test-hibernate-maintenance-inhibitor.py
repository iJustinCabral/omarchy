"""Fake libsystemd ABI + local unprivileged pipes/signals; no live inhibitor."""
import ctypes
import errno
import importlib.util
import os
from pathlib import Path
import signal
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("tested_maintenance_inhibitor", Path(__file__).parents[1] / "hibernate/maintenance_inhibitor.py")
I = importlib.util.module_from_spec(spec)
spec.loader.exec_module(I)
REAL_FSTAT = os.fstat


class Function:
  def __init__(self, function): self.function = function
  def __call__(self, *arguments): return self.function(*arguments)


class FakeBus:
  def __init__(self, fd):
    self.fd, self.calls, self.results = fd, [], {}
    self.null_bus, self.null_reply, self.bad_fd = False, False, None
    for name in ("sd_bus_open_system", "sd_bus_set_allow_interactive_authorization",
      "sd_bus_set_method_call_timeout", "sd_bus_call_method", "sd_bus_message_has_signature",
      "sd_bus_message_read_basic", "sd_bus_message_at_end", "sd_bus_message_unref",
      "sd_bus_flush_close_unref"):
      setattr(self, name, Function(lambda *args, name=name: self.call(name, args)))

  def call(self, name, args):
    self.calls.append((name, args))
    if name == "sd_bus_open_system":
      ctypes.cast(args[0], ctypes.POINTER(ctypes.c_void_p))[0] = 0 if self.null_bus else 11
    elif name == "sd_bus_call_method":
      ctypes.cast(args[6], ctypes.POINTER(ctypes.c_void_p))[0] = 0 if self.null_reply else 12
    elif name == "sd_bus_message_read_basic":
      ctypes.cast(args[2], ctypes.POINTER(ctypes.c_int))[0] = self.fd if self.bad_fd is None else self.bad_fd
    elif name == "sd_bus_message_unref":
      os.close(self.fd)
      self.fd = None
    default = 1 if name in ("sd_bus_message_has_signature", "sd_bus_message_read_basic", "sd_bus_message_at_end") else 0
    return self.results.get(name, default)


class OwnerFD(unittest.TestCase):
  def setUp(self):
    self.read, borrowed = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    self.bus = FakeBus(borrowed)
    self.handles, self.power_calls = [], []
    self.power_error = None
    self.power = SimpleNamespace(__file__=str(I.POWER), WHO=I.WHO, WHY=I.WHY,
      _power_idle=lambda pid: self.power_query("idle", pid),
      _power_ongoing=lambda pid: self.power_query("ongoing", pid))
    self.patches = [patch.object(I, "_native", lambda: None), patch.object(I.ctypes, "CDLL", self.library),
      patch.object(I.os, "fstat", self.root_fifo_metadata)]
    for replacement in self.patches: replacement.start()
    self.addCleanup(self.cleanup)

  def root_fifo_metadata(self, fd):
    info = REAL_FSTAT(fd)
    # The real local pipe belongs to the unprivileged tester; only the fake
    # ABI's metadata models the root logind FIFO. No host ownership changes.
    return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_mode=info.st_mode,
      st_uid=0, st_gid=info.st_gid) if stat.S_ISFIFO(info.st_mode) else info

  def library(self, path):
    self.assertEqual(path, "/usr/lib/libsystemd.so.0")
    return self.bus

  def power_query(self, mode, pid):
    self.power_calls.append((mode, pid))
    self.assertEqual(pid, os.getpid())
    if self.power_error is not None: raise self.power_error

  def cleanup(self):
    for handle in self.handles:
      if handle.fd is not None:
        os.close(handle.fd)
        handle.fd = None
    if self.bus.fd is not None: os.close(self.bus.fd)
    if self.read is not None: os.close(self.read)
    for replacement in reversed(self.patches): replacement.stop()

  def acquire(self):
    result = I.acquire(self.power)
    self.handles.append(result)
    return result

  def test_fixed_exact_abi_duplicate_and_cleanup(self):
    borrowed = self.bus.fd
    handle = self.acquire()
    with self.assertRaises(OSError): REAL_FSTAT(borrowed)
    self.assertIsNone(self.bus.fd)
    self.assertFalse(os.get_inheritable(handle.fd))
    self.assertEqual(REAL_FSTAT(handle.fd).st_ino, REAL_FSTAT(self.read).st_ino)
    names = [name for name, _ in self.bus.calls]
    self.assertEqual(names, ["sd_bus_open_system", "sd_bus_set_allow_interactive_authorization",
      "sd_bus_set_method_call_timeout", "sd_bus_call_method", "sd_bus_message_has_signature",
      "sd_bus_message_read_basic", "sd_bus_message_at_end", "sd_bus_message_unref", "sd_bus_flush_close_unref"])
    args = self.bus.calls[3][1]
    self.assertEqual(args[1:6], (*I.LOGIN, b"Inhibit", None))
    self.assertEqual(args[7], b"ssss")
    self.assertEqual([value.value for value in args[8:]], [b"sleep:shutdown", I.WHO.encode(), I.WHY.encode(), b"block"])
    self.assertEqual(self.bus.calls[1][1][1], 0)
    self.assertEqual(self.bus.calls[2][1][1], 5_000_000)
    self.assertEqual(self.bus.sd_bus_message_read_basic.argtypes, [ctypes.c_void_p, ctypes.c_char, ctypes.c_void_p])
    self.assertEqual(self.bus.sd_bus_call_method.restype, ctypes.c_int)
    self.assertEqual(self.power_calls, [("idle", os.getpid())])
    handle.check()
    self.assertEqual(self.power_calls[-1], ("ongoing", os.getpid()))
    handle.close()
    with self.assertRaises(ValueError): handle.check()
    handle.close()  # explicit safe-close idempotence

  def test_workspace_gate_precedes_library_and_queries(self):
    with patch.object(I, "_native", side_effect=ValueError("gate")):
      with self.assertRaises(ValueError): I.acquire(self.power)
    self.assertEqual(self.bus.calls, [])
    self.assertEqual(self.power_calls, [])

  def test_real_workspace_gate_refuses_even_mock_root(self):
    with patch.object(I.os, "getresuid", lambda: (0, 0, 0)):
      # Invoke original gate from a separately loaded module, not patched seam.
      other_spec = importlib.util.spec_from_file_location("inhibitor_gate_only", Path(I.__file__))
      other = importlib.util.module_from_spec(other_spec)
      other_spec.loader.exec_module(other)
      with self.assertRaises(ValueError): other.acquire(self.power)
    self.assertEqual(self.bus.calls, [])

  def test_wrong_power_context_refused_before_bus(self):
    for field, value in (("WHO", "other"), ("WHY", "other"), ("__file__", "/tmp/boot_policy_native.py"), ("_power_idle", None)):
      original = getattr(self.power, field)
      setattr(self.power, field, value)
      with self.assertRaises(ValueError): I.acquire(self.power)
      setattr(self.power, field, original)
    self.assertEqual(self.bus.calls, [])

  def test_each_negative_abi_result_cleans_handles(self):
    for name in ("sd_bus_open_system", "sd_bus_set_allow_interactive_authorization", "sd_bus_set_method_call_timeout",
      "sd_bus_call_method", "sd_bus_message_read_basic"):
      with self.subTest(name=name):
        self.bus.calls.clear()
        self.bus.results = {name: -errno.EIO}
        # A fresh local message-owned reference for each fake reply.
        if self.bus.fd is None: self.bus.fd = os.dup(self.read)
        with self.assertRaises(OSError): I.acquire(self.power)
        names = [item[0] for item in self.bus.calls]
        self.assertEqual(names[-1], "sd_bus_flush_close_unref")
        if name in ("sd_bus_call_method", "sd_bus_message_read_basic"):
          self.assertIn("sd_bus_message_unref", names)
    self.assertEqual(self.power_calls, [])

  def test_malformed_reply_refused_before_duplication(self):
    for name, result in (("sd_bus_message_has_signature", 0), ("sd_bus_message_read_basic", 0),
      ("sd_bus_message_at_end", 0), ("sd_bus_message_has_signature", -errno.EBADMSG)):
      with self.subTest(name=name, result=result):
        self.bus.results = {name: result}
        if self.bus.fd is None: self.bus.fd = os.dup(self.read)
        with self.assertRaises((ValueError, OSError)): I.acquire(self.power)
        self.assertIsNone(self.bus.fd)
    self.assertEqual(self.power_calls, [])

  def test_missing_reply_and_stdio_fd_rejected(self):
    self.bus.null_reply = True
    with self.assertRaises(ValueError): I.acquire(self.power)
    self.bus.null_reply = False
    self.bus.bad_fd = 1
    with self.assertRaises(ValueError): I.acquire(self.power)
    self.assertEqual(self.power_calls, [])

  def test_missing_bus_pointer_never_calls_method(self):
    self.bus.null_bus = True
    with self.assertRaises(ValueError): I.acquire(self.power)
    self.assertEqual([item[0] for item in self.bus.calls], ["sd_bus_open_system"])

  def test_dup_failure_keeps_message_cleanup(self):
    with patch.object(I.fcntl, "fcntl", side_effect=OSError(errno.EMFILE, "fake dup failure")):
      with self.assertRaises(OSError): I.acquire(self.power)
    self.assertIsNone(self.bus.fd)
    self.assertEqual(self.bus.calls[-1][0], "sd_bus_flush_close_unref")

  def test_post_duplicate_cleanup_failure_does_not_leak_owned_fd(self):
    duplicates = []
    actual = I.fcntl.fcntl
    def record(fd, operation, *args):
      result = actual(fd, operation, *args)
      if operation == I.fcntl.F_DUPFD_CLOEXEC: duplicates.append(result)
      return result
    original = self.bus.sd_bus_message_unref.function
    def interrupted(*args):
      original(*args)
      raise KeyboardInterrupt()
    self.bus.sd_bus_message_unref.function = interrupted
    with patch.object(I.fcntl, "fcntl", record):
      with self.assertRaises(KeyboardInterrupt): I.acquire(self.power)
    self.assertEqual(len(duplicates), 1)
    with self.assertRaises(OSError): REAL_FSTAT(duplicates[0])
    self.assertEqual(self.bus.calls[-1][0], "sd_bus_flush_close_unref")

  def test_strict_startup_failure_closes_only_owned_duplicate(self):
    self.power_error = ValueError("queued job at startup")
    duplicates = []
    actual = I.fcntl.fcntl
    def record(fd, operation, *args):
      result = actual(fd, operation, *args)
      if operation == I.fcntl.F_DUPFD_CLOEXEC: duplicates.append(result)
      return result
    with patch.object(I.fcntl, "fcntl", record):
      with self.assertRaises(ValueError): self.acquire()
    self.assertEqual(len(duplicates), 1)
    with self.assertRaises(OSError): REAL_FSTAT(duplicates[0])
    self.assertIsNone(self.bus.fd)

  def test_runtime_power_failure_retains_fd_until_explicit_close(self):
    handle = self.acquire()
    for error in (ValueError("power scheduled"), KeyboardInterrupt()):
      self.power_error = error
      with self.assertRaises(type(error)): handle.check()
      self.assertIsNotNone(handle.fd)
      REAL_FSTAT(handle.fd)
    handle.close()

  def test_fifo_reader_loss_refuses_without_power_query_and_retains_fd(self):
    handle = self.acquire()
    os.close(self.read)
    self.read = None
    count = len(self.power_calls)
    with self.assertRaises(ValueError): handle.check()
    self.assertEqual(len(self.power_calls), count)
    REAL_FSTAT(handle.fd)
    handle.close()

  def test_runtime_inheritable_descriptor_refuses_and_retains(self):
    handle = self.acquire()
    os.set_inheritable(handle.fd, True)
    with self.assertRaises(ValueError): handle.check()
    self.assertIsNotNone(handle.fd)
    os.set_inheritable(handle.fd, False)
    handle.close()

  def test_replaced_descriptor_not_queried_or_closed(self):
    handle = self.acquire()
    fd = handle.fd
    os.close(fd)
    with tempfile.TemporaryFile() as replacement:
      os.dup2(replacement.fileno(), fd, inheritable=False)
      count = len(self.power_calls)
      with self.assertRaises(ValueError): handle.check()
      with self.assertRaises(ValueError): handle.close()
      self.assertEqual(len(self.power_calls), count)
      self.assertTrue(stat.S_ISREG(REAL_FSTAT(fd).st_mode))

  def test_wrong_process_cannot_check_or_close(self):
    handle = self.acquire()
    with patch.object(I.os, "getpid", lambda: handle.owner + 1):
      with self.assertRaises(ValueError): handle.check()
      with self.assertRaises(ValueError): handle.close()
    handle.close()

  def test_no_automatic_release_api(self):
    self.assertFalse(hasattr(I.OwnerInhibitor, "__enter__"))
    self.assertFalse(hasattr(I.OwnerInhibitor, "__exit__"))
    self.assertFalse(hasattr(I.OwnerInhibitor, "__del__"))


class StopPolicy(unittest.TestCase):
  def setUp(self):
    self.previous = {number: signal.getsignal(number) for number in I.STOP_SIGNALS}
    self.addCleanup(self.restore)

  def restore(self):
    for number, handler in self.previous.items(): signal.signal(number, handler)

  def test_real_local_signals_record_only_and_restore_explicitly(self):
    latch = I.StopLatch().arm()
    latch.check()
    for number in I.STOP_SIGNALS: signal.raise_signal(number)
    signal.raise_signal(signal.SIGTERM)
    self.assertTrue(latch.requested)
    self.assertEqual(latch.signals, I.STOP_SIGNALS)
    with self.assertRaises(I.StopRequested): latch.check()
    self.assertFalse(hasattr(latch, "__exit__"))
    latch.safe_exit()
    for number in I.STOP_SIGNALS: self.assertEqual(signal.getsignal(number), self.previous[number])
    with self.assertRaises(ValueError): latch.check()

  def test_exception_does_not_restore_handlers(self):
    latch = I.StopLatch().arm()
    try: raise RuntimeError("synthetic retained recovery")
    except RuntimeError: pass
    for number in I.STOP_SIGNALS: self.assertEqual(signal.getsignal(number), latch.handler)
    signal.raise_signal(signal.SIGTERM)
    self.assertTrue(latch.requested)
    latch.safe_exit()

  def test_unarmed_and_double_arm_refused(self):
    latch = I.StopLatch()
    with self.assertRaises(ValueError): latch.check()
    with self.assertRaises(ValueError): latch.safe_exit()
    latch.arm()
    with self.assertRaises(ValueError): latch.arm()
    latch.safe_exit()

  def test_changed_handler_refuses_ambiguous_restore(self):
    latch = I.StopLatch().arm()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    with self.assertRaises(ValueError): latch.check()
    with self.assertRaises(ValueError): latch.safe_exit()
    self.assertIsNotNone(latch.previous)
    self.assertEqual(signal.getsignal(signal.SIGTERM), latch.handler)
    signal.signal(signal.SIGHUP, latch.handler)
    latch.safe_exit()

  def test_arm_failure_rolls_back_before_mutation(self):
    actual = signal.signal
    def fail(number, handler):
      if number == signal.SIGHUP: raise ValueError("fake signal install refusal")
      return actual(number, handler)
    latch = I.StopLatch()
    with patch.object(I.signal, "signal", fail):
      with self.assertRaises(ValueError): latch.arm()
    self.assertIsNone(latch.previous)
    for number in I.STOP_SIGNALS: self.assertEqual(signal.getsignal(number), self.previous[number])


if __name__ == "__main__": unittest.main()
