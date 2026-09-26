// SPDX-License-Identifier: GPL-2.0
/* Offline prototype only. No firmware initialization, DMA, IRQs or root reset. */
#include <linux/dmi.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/string.h>

#define ANS_CC 0x14
#define ANS_CSTS 0x1c
struct mba_guard {
  struct pci_dev *functions[4];
  void __iomem *ans_regs;
  unsigned long async_mask, original_master_mask;
  bool active, gate_failed;
};
static struct mba_guard *instance;
static bool armed, arm_consumed;
static bool gate_active, gate_failed;
static unsigned int gates;
static char vector_prefix[25];
module_param(arm_consumed, bool, 0400);
module_param(gates, uint, 0400);
module_param(gate_active, bool, 0400);
module_param(gate_failed, bool, 0400);
module_param_string(vector_prefix, vector_prefix, sizeof(vector_prefix), 0400);

static int mba_set_arm_prefix(const char *value, const struct kernel_param *parameter)
{
  size_t length = strcspn(value, "\n"), i;

  (void)parameter;
  if (!instance || armed || arm_consumed)
    return -EPERM;
  if (length != 24 || (value[length] != '\0' && value[length + 1] != '\0'))
    return -EINVAL;
  for (i = 0; i < length; i++)
    if (!((value[i] >= '0' && value[i] <= '9') ||
          (value[i] >= 'a' && value[i] <= 'f')))
      return -EINVAL;
  memcpy(vector_prefix, value, 24);
  vector_prefix[24] = '\0';
  arm_consumed = true;
  armed = true;
  return 0;
}

static int mba_get_arm_prefix(char *value, const struct kernel_param *parameter)
{
  (void)parameter;
  return sprintf(value, "%u\n", armed);
}
static const struct kernel_param_ops arm_ops = {
  .set = mba_set_arm_prefix, .get = mba_get_arm_prefix,
};
module_param_cb(arm_prefix, &arm_ops, NULL, 0600);

static int mba_prepare(struct device *dev)
{
  (void)dev;
  return armed ? 0 : -EPERM;
}

static int mba_freeze(struct device *dev)
{
  (void)dev;
  return armed ? 0 : -EPERM;
}

static int mba_freeze_noirq(struct device *dev)
{
  struct mba_guard *guard = pci_get_drvdata(to_pci_dev(dev));
  unsigned long mask = 0;
  u32 cc, csts;
  u16 command;
  size_t i;
  int error = 0;

  if (!armed || guard->active || gates)
    return -EPERM;
  armed = false;
  gates++;
  gate_failed = true;
  guard->gate_failed = true;
  /* Main quiesce has completed before ANY noirq callback. Independently
   * require the root controller to be disabled before touching its MASTER.
   * An inaccessible BAR must never be interpreted as a disabled controller.
   */
  cc = readl(guard->ans_regs + ANS_CC);
  csts = readl(guard->ans_regs + ANS_CSTS);
  if (cc == ~0U || csts == ~0U || pci_is_enabled(guard->functions[0]))
    return -EBUSY;
  /* nvme_simple_suspend uses shutdown=true: EN/RDY may remain set after
   * normal shutdown completes. Require that documented completed state or
   * a fully reset controller, as well as disabled Linux PCI ownership.
   */
  if (!((!(cc & 1) && !(csts & 1)) ||
        ((cc & (3U << 14)) == (1U << 14) &&
         (csts & (3U << 2)) == (2U << 2))))
    return -EBUSY;
  for (i = 0; i < ARRAY_SIZE(guard->functions); i++) {
    if (pci_read_config_word(guard->functions[i], PCI_COMMAND, &command) ||
        command == 0xffff)
      return -EIO;
    if (command & PCI_COMMAND_MASTER)
      mask |= BIT(i);
  }
  if (mask & BIT(0))
    return -EBUSY;
  guard->original_master_mask = mask;
  guard->active = true;
  gate_active = true;
  /* Never unwind a partial gate here: PCI core restores saved config BEFORE
   * the thaw_noirq callback. Clear/scrub EVERY sibling even after an error.
   */
  for (i = 0; i < ARRAY_SIZE(guard->functions); i++) {
    pci_clear_master(guard->functions[i]);
    if (pci_read_config_word(guard->functions[i], PCI_COMMAND, &command) ||
        (command & PCI_COMMAND_MASTER))
      error = -EIO;
  }
  for (i = 0; i < ARRAY_SIZE(guard->functions); i++) {
    if (pci_save_state(guard->functions[i]))
      error = -EIO;
    /* pci_save_state sets state_saved before optional capability errors;
     * also mask COMMAND in its snapshot if a failed clear left MASTER set.
     * Recovery must not replay that bit before main callbacks finish.
     */
    guard->functions[i]->saved_config_space[PCI_COMMAND / 4] &= ~PCI_COMMAND_MASTER;
  }
  guard->gate_failed = error != 0;
  gate_failed = guard->gate_failed;
  return error;
}

static int mba_thaw_noirq(struct device *dev)
{
  struct mba_guard *guard = pci_get_drvdata(to_pci_dev(dev));
  u16 command;
  size_t i;
  int error = 0;

  if (!guard->active)
    return 0;
  for (i = 0; i < ARRAY_SIZE(guard->functions); i++) {
    if (pci_read_config_word(guard->functions[i], PCI_COMMAND, &command) ||
        (command & PCI_COMMAND_MASTER)) {
      pci_clear_master(guard->functions[i]);
      error = -EIO;
    }
  }
  if (error) {
    guard->gate_failed = true;
    gate_failed = true;
  }
  return error;
}

static void mba_complete(struct device *dev)
{
  struct mba_guard *guard = pci_get_drvdata(to_pci_dev(dev));
  u16 command;
  size_t i;

  if (!guard->active)
    return;
  /* dpm_complete runs after ALL ordinary main recovery callbacks. ANS may
   * already have enabled MASTER for fresh reset queues; never clear that bit.
   * Restore only bits known enabled at the gate, including partial failure.
   */
  for (i = 0; i < ARRAY_SIZE(guard->functions); i++) {
    if (!(guard->original_master_mask & BIT(i)))
      continue;
    pci_set_master(guard->functions[i]);
    if (pci_read_config_word(guard->functions[i], PCI_COMMAND, &command) ||
        command == 0xffff || !(command & PCI_COMMAND_MASTER)) {
      guard->gate_failed = true;
      gate_failed = true;
    }
  }
  guard->active = false;
  gate_active = false;
}

static void mba_release(struct mba_guard *guard)
{
  size_t i;

  if (guard->ans_regs)
    iounmap(guard->ans_regs);
  for (i = 0; i < ARRAY_SIZE(guard->functions); i++) {
    if (!guard->functions[i])
      continue;
    if (guard->async_mask & BIT(i))
      device_enable_async_suspend(&guard->functions[i]->dev);
    pci_dev_put(guard->functions[i]);
  }
  kfree(guard);
}

static int mba_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
  static const u16 ids[] = { 0x2005, 0x1801, 0x1802, 0x1803 };
  struct mba_guard *guard;
  size_t i;
  int error = -ENODEV;

  (void)id;
  if (instance || PCI_FUNC(pdev->devfn) != 1)
    return -ENODEV;
  guard = kzalloc(sizeof(*guard), GFP_KERNEL);
  if (!guard)
    return -ENOMEM;
  for (i = 0; i < ARRAY_SIZE(guard->functions); i++) {
    guard->functions[i] = pci_get_slot(pdev->bus, PCI_DEVFN(PCI_SLOT(pdev->devfn), i));
    if (!guard->functions[i] || guard->functions[i]->vendor != PCI_VENDOR_ID_APPLE ||
        guard->functions[i]->device != ids[i])
      goto fail;
    if (i == 0) {
      if (!guard->functions[i]->driver ||
          strcmp(guard->functions[i]->driver->name, "nvme") ||
          guard->functions[i]->class != PCI_CLASS_STORAGE_EXPRESS ||
          !(pci_resource_flags(guard->functions[i], 0) & IORESOURCE_MEM) ||
          pci_resource_len(guard->functions[i], 0) < ANS_CSTS + 4)
        goto fail;
    } else if (i != 1 && guard->functions[i]->driver) {
      goto fail;
    }
  }
  /* Map only standard ANS status registers read-only; no BAR/PCI enable. */
  guard->ans_regs = ioremap(pci_resource_start(guard->functions[0], 0), ANS_CSTS + 4);
  if (!guard->ans_regs) {
    error = -ENOMEM;
    goto fail;
  }
  for (i = 0; i < ARRAY_SIZE(guard->functions); i++) {
    if (device_async_suspend_enabled(&guard->functions[i]->dev))
      guard->async_mask |= BIT(i);
    device_disable_async_suspend(&guard->functions[i]->dev);
  }
  pci_set_drvdata(pdev, guard);
  instance = guard;
  return 0;
fail:
  mba_release(guard);
  return error;
}

static void mba_remove(struct pci_dev *pdev)
{
  struct mba_guard *guard = pci_get_drvdata(pdev);

  /* A forced unbind during active PM is unsupported; never reopen DMA here. */
  WARN_ON(guard->active);
  instance = NULL;
  pci_set_drvdata(pdev, NULL);
  mba_release(guard);
}
static const struct dev_pm_ops mba_pm = {
  .prepare = mba_prepare, .freeze = mba_freeze,
  .freeze_noirq = mba_freeze_noirq, .thaw_noirq = mba_thaw_noirq,
  .complete = mba_complete,
};
static const struct pci_device_id mba_ids[] = {
  { PCI_DEVICE(PCI_VENDOR_ID_APPLE, 0x1801) }, { }
};
static struct pci_driver mba_driver = {
  .name = "mba_hibernate_cold_pci_guard", .id_table = mba_ids,
  .probe = mba_probe, .remove = mba_remove, .driver.pm = &mba_pm,
};
static int __init mba_init(void)
{
  if (armed || arm_consumed || gate_active || gate_failed || gates || vector_prefix[0] ||
      !dmi_match(DMI_PRODUCT_NAME, "MacBookAir9,1"))
    return -EPERM;
  return pci_register_driver(&mba_driver);
}
static void __exit mba_exit(void)
{
  armed = false;
  pci_unregister_driver(&mba_driver);
}
module_init(mba_init);
module_exit(mba_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Offline cold restore shared PCI MASTER isolation prototype");
