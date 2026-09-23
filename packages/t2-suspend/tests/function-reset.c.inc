#define BRCMF_ARMCR4_CPUHALT BIT(5)

/* Runtime recovery only; initial probe retains the packaged reset sequence. */
static int brcmf_pcie_recovery_flr(struct brcmf_pciedev_info *devinfo)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct brcmf_bus *bus = dev_get_drvdata(&pdev->dev);
	static const u16 offsets[] = { 0x70, 0x74, 0x80, 0x84, 0x88 };
	struct brcmf_core *arm;
	u32 saved[ARRAY_SIZE(offsets)], value;
	int i, ret;

	if (pdev->vendor != PCI_VENDOR_ID_BROADCOM || pdev->device != 0x4488 ||
	    PCI_FUNC(pdev->devfn) || devinfo->ci->chip != BRCM_CC_4377_CHIP_ID ||
	    !dmi_match(DMI_SYS_VENDOR, "Apple Inc.") ||
	    !dmi_match(DMI_PRODUCT_NAME, "MacBookAir9,1"))
		return -ENODEV;
	arm = brcmf_chip_get_core(devinfo->ci, BCMA_CORE_ARM_CR4);
	if (!arm)
		return -ENODEV;
	ret = pcie_reset_flr(pdev, true);
	if (ret)
		return ret;

	/* A failed attempt must never invoke the shared watchdog. */
	devinfo->recovery_flr = true;
	brcmf_pcie_fwcon_timer(devinfo, false);
	brcmf_bus_change_state(bus, BRCMF_BUS_DOWN);
	devinfo->state = BRCMFMAC_PCIE_STATE_DOWN;
	brcmf_pcie_release_irq(devinfo);
	pci_cfg_access_lock(pdev);
	pci_clear_master(pdev);
	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		ret = pci_read_config_dword(pdev, offsets[i], &saved[i]);
		if (ret || saved[i] == ~0U) {
			ret = ret ? pcibios_err_to_errno(ret) : -EIO;
			goto unlock;
		}
	}
	ret = pci_save_state(pdev);
	if (ret)
		goto unlock;
	/* As in PCI core reset, disable decoding and bus mastering during FLR. */
	ret = pci_write_config_word(pdev, PCI_COMMAND, PCI_COMMAND_INTX_DISABLE);
	if (ret) {
		ret = pcibios_err_to_errno(ret);
		goto unlock;
	}
	dev_info(&pdev->dev, "t2wifi-recovery: starting function 0 FLR\n");
	ret = pcie_reset_flr(pdev, false);
	pci_restore_state(pdev);
	if (ret)
		goto unlock;
	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		ret = pci_write_config_dword(pdev, offsets[i], saved[i]);
		if (ret) {
			ret = pcibios_err_to_errno(ret);
			goto unlock;
		}
		ret = pci_read_config_dword(pdev, offsets[i], &value);
		if (ret || value != saved[i]) {
			ret = ret ? pcibios_err_to_errno(ret) : -EIO;
			goto unlock;
		}
	}
	/* FLR resets the PCI function. Explicitly hold the Wi-Fi CPU for the
	 * existing firmware download path; do not assume FLR halted that CPU.
	 */
	brcmf_chip_set_passive(devinfo->ci);
	brcmf_chip_coredisable(arm, BRCMF_ARMCR4_CPUHALT, 0);
	if (brcmf_chip_iscoreup(arm)) {
		ret = -EIO;
		goto unlock;
	}
	dev_info(&pdev->dev, "t2wifi-recovery: FLR complete; Wi-Fi CPU held\n");
	ret = 0;
unlock:
	pci_cfg_access_unlock(pdev);
	if (ret)
		dev_err(&pdev->dev, "t2wifi-recovery: stopped (%d); no watchdog fallback\n", ret);
	return ret;
}
