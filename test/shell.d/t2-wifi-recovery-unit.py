import importlib.util
from pathlib import Path
import unittest
import tempfile
import os
import fcntl
from unittest.mock import patch, MagicMock
spec = importlib.util.spec_from_file_location('recovery', Path(__file__).resolve().parents[2]/'install/hardware/apple/t2-wifi-recovery.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Trigger(unittest.TestCase):
  def setUp(self):
    self.entry = {'_BOOT_ID': 'abc', '_TRANSPORT': 'kernel', '__MONOTONIC_TIMESTAMP': '200000000', 'MESSAGE': 'ieee80211 phy0: brcmf_msgbuf_query_dcmd: Timeout on response for query command'}
    self.dev = {'phy': 'phy0', 'enabled': True, 'connected': False}
    self.state = {'attempts': 0, 'last_attempt': -120}
  def check(self):
    return m.eligible(self.entry, 'abc', 190, 201, self.dev, self.state)
  def test_confirmed_stall(self): self.assertTrue(self.check())
  def test_other_boot(self):
    self.entry['_BOOT_ID'] = 'def'; self.assertFalse(self.check())
  def test_userspace_message(self):
    self.entry['_TRANSPORT'] = 'stdout'; self.assertFalse(self.check())
  def test_other_phy(self):
    self.dev['phy'] = 'phy1'; self.assertFalse(self.check())
  def test_disabled(self):
    self.dev['enabled'] = False; self.assertFalse(self.check())
  def test_connected(self):
    self.dev['connected'] = True; self.assertFalse(self.check())
  def test_old_event(self):
    self.entry['__MONOTONIC_TIMESTAMP'] = '100000000'; self.assertFalse(self.check())
  def test_future_event(self):
    self.entry['__MONOTONIC_TIMESTAMP'] = '250000000'; self.assertFalse(self.check())
  def test_exhausted(self):
    self.state['attempts'] = 3; self.assertFalse(self.check())
  def test_cooldown(self):
    self.state['last_attempt'] = 195; self.assertFalse(self.check())
  def test_malformed_timestamp(self):
    self.entry['__MONOTONIC_TIMESTAMP'] = 'x'; self.assertFalse(self.check())
  def test_other_error(self):
    self.entry['MESSAGE'] = 'ieee80211 phy0: brcmf_p2p_create_p2pdev: set p2p_disc error'; self.assertFalse(self.check())

class ResetSafety(unittest.TestCase):
  def setUp(self):
    self.dev = {'index': 1, 'interface': 'wlp115s0f0', 'enabled': True, 'connected': False, 'reset': '/unused'}
    self.state = {'attempts': 0, 'last_attempt': -120}
  def test_cancel_if_user_disabled(self):
    changed = {**self.dev, 'enabled': False}
    with patch.object(m, 'guard'), patch.object(m, 'save') as save, patch.object(m, 'device', return_value=changed), patch.object(m, 'Path') as path, patch.object(m, 'log'):
      m.recover_locked(self.dev, self.state)
    path.assert_not_called()
    save.assert_called_once()
    self.assertEqual(self.state['attempts'], 1)
  def test_cancel_if_new_interface_already_exists(self):
    changed = {**self.dev, 'index': 2}
    with patch.object(m, 'guard'), patch.object(m, 'save'), patch.object(m, 'device', return_value=changed), patch.object(m, 'Path') as path, patch.object(m, 'log'):
      m.recover_locked(self.dev, self.state)
    path.assert_not_called()
  def test_budget_saved_before_reset(self):
    order = []
    reset = MagicMock()
    reset.write_text.side_effect = lambda _: order.append('reset')
    after = {**self.dev, 'index': 2, 'enabled': False}
    with patch.object(m, 'guard'), patch.object(m, 'save', side_effect=lambda _: order.append('save')), patch.object(m, 'device', side_effect=[self.dev, after]), patch.object(m, 'Path', return_value=reset), patch.object(m, 'log') as log:
      m.recover_locked(self.dev, self.state)
    self.assertEqual(order, ['save', 'reset'])
    self.assertEqual(log.call_args.args[0], 'RADIO_BLOCKED_DURING_RECOVERY')
  def test_enodev_during_replacement_keeps_verifying(self):
    after = {**self.dev, 'index': 2, 'connected': True}
    nm = MagicMock(returncode=0, stdout='100 (connected)')
    with patch.object(m, 'guard'), patch.object(m, 'save'), patch.object(m, 'device', side_effect=[self.dev, OSError(19, 'No such device'), after]), patch.object(m, 'Path'), patch.object(m.subprocess, 'run', return_value=nm), patch.object(m.time, 'sleep'), patch.object(m, 'log') as log:
      m.recover_locked(self.dev, self.state)
    self.assertEqual(log.call_args.args[0], 'RECOVERED')

  def test_success_requires_new_interface_and_nm(self):
    after = {**self.dev, 'index': 2, 'connected': True}
    nm = MagicMock(returncode=0, stdout='100 (connected)')
    with patch.object(m, 'guard'), patch.object(m, 'save'), patch.object(m, 'device', side_effect=[self.dev, after]), patch.object(m, 'Path'), patch.object(m.subprocess, 'run', return_value=nm), patch.object(m, 'log') as log:
      m.recover_locked(self.dev, self.state)
    self.assertEqual(log.call_args.args[0], 'RECOVERED')

class Hardware(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.root = Path(self.temp.name)
    self.patch = patch.object(m, 'SYS', self.root); self.patch.start()
    self.env = patch.dict(os.environ, {}, clear=True); self.env.start()
    dmi = self.root/'class/dmi/id'; dmi.mkdir(parents=True)
    (dmi/'sys_vendor').write_text('Apple Inc.')
    (dmi/'product_name').write_text('MacBookAir9,1')
    self.pci = self.root/'bus/pci/devices'; self.pci.mkdir(parents=True)
    self.add('0000:21:00.0', '0x106b', '0x1801')
    self.wifi = self.add('0000:22:00.0', '0x14e4', '0x4488')
  def add(self, address, vendor, device):
    p = self.pci/address; p.mkdir()
    (p/'vendor').write_text(vendor); (p/'device').write_text(device)
    return p
  def tearDown(self):
    self.patch.stop(); self.env.stop(); self.temp.cleanup()
  def test_dynamic_pci_address(self): self.assertEqual(m.hardware(), self.wifi)
  def test_non_apple(self):
    (self.root/'class/dmi/id/sys_vendor').write_text('Other')
    with self.assertRaises(RuntimeError): m.hardware()
  def test_no_t2(self):
    (self.pci/'0000:21:00.0'/'device').write_text('0x0000')
    with self.assertRaises(RuntimeError): m.hardware()
  def test_bcm4364_never_opted_in(self):
    os.environ['OMARCHY_T2_WIFI_ALLOW_UNTESTED_MODEL'] = '1'
    (self.wifi/'device').write_text('0x4464')
    with self.assertRaises(RuntimeError): m.hardware()
  def test_other_model_requires_opt_in(self):
    (self.root/'class/dmi/id/product_name').write_text('MacBookPro16,1')
    with self.assertRaises(RuntimeError): m.hardware()
    os.environ['OMARCHY_T2_WIFI_ALLOW_UNTESTED_MODEL'] = '1'
    self.assertEqual(m.hardware(), self.wifi)
  def test_ambiguous_wifi_devices(self):
    self.add('0000:23:00.0', '0x14e4', '0x4488')
    with self.assertRaises(RuntimeError): m.hardware()
  def test_wrong_bound_driver(self):
    driver = self.root/'other'; driver.mkdir()
    (self.wifi/'driver').symlink_to(driver)
    with self.assertRaises(RuntimeError): m.guard()

class SleepCoordination(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.root = Path(self.temp.name)
    self.lock = self.root/'lock'
    self.state = self.root/'state'
    self.patches = [patch.object(m, 'SLEEP_LOCK', self.lock), patch.object(m, 'SLEEP_STATE', self.state)]
    for p in self.patches: p.start()
  def tearDown(self):
    for p in self.patches: p.stop()
    self.temp.cleanup()
  def test_sleep_prepared_prevents_reset(self):
    self.state.write_text('prepared')
    with patch.object(m, 'recover_locked') as reset, patch.object(m, 'log'):
      m.recover({}, {})
      reset.assert_not_called()
  def test_sleep_running_prevents_reset(self):
    with self.lock.open('a') as lock:
      fcntl.flock(lock, fcntl.LOCK_EX)
      with patch.object(m, 'recover_locked') as reset, patch.object(m, 'log'):
        m.recover({}, {})
        reset.assert_not_called()
  def test_recovery_holds_lock_through_verification(self):
    def reset(*_):
      with self.lock.open('a') as other:
        with self.assertRaises(BlockingIOError):
          fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with patch.object(m, 'settle_enabled', return_value=True), patch.object(m, 'recover_locked', side_effect=reset): m.recover({}, {})

class EnableSettlement(unittest.TestCase):
  def setUp(self):
    self.dev = {'index': 3, 'enabled': True, 'connected': False}
  def test_original_radio_survives_persistence_window(self):
    with patch.object(m, 'device', return_value=self.dev), patch.object(m.time, 'sleep') as sleep, patch.object(m, 'log'):
      self.assertTrue(m.settle_enabled(self.dev))
    self.assertEqual(sum(c.args[0] for c in sleep.call_args_list), 8)
  def test_off_request_cancels_without_forcing_on(self):
    with patch.object(m, 'device', side_effect=[self.dev, {**self.dev, 'enabled': False}]), patch.object(m.time, 'sleep'), patch.object(m, 'log'):
      self.assertFalse(m.settle_enabled(self.dev))
  def test_connection_obviates_reset(self):
    with patch.object(m, 'device', return_value={**self.dev, 'connected': True}), patch.object(m.time, 'sleep'), patch.object(m, 'log'):
      self.assertFalse(m.settle_enabled(self.dev))
  def test_replacement_cancels_stale_trigger(self):
    with patch.object(m, 'device', return_value={**self.dev, 'index': 5}), patch.object(m.time, 'sleep'), patch.object(m, 'log'):
      self.assertFalse(m.settle_enabled(self.dev))

unittest.main()
