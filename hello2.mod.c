#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x28950ef1, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x1b6314fd, __VMLINUX_SYMBOL_STR(in_aton) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x195c9f2c, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x34c11ce1, __VMLINUX_SYMBOL_STR(dev_queue_xmit) },
	{ 0xa6862bef, __VMLINUX_SYMBOL_STR(skb_push) },
	{ 0xb65b0187, __VMLINUX_SYMBOL_STR(skb_checksum) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x2ac95217, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0xaf3f0d3e, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x548ddad5, __VMLINUX_SYMBOL_STR(dev_get_by_name) },
	{ 0x8070df92, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "C2AA1BD4BE9B3E0484FAF8D");
MODULE_INFO(rhelversion, "7.6");
#ifdef RETPOLINE
	MODULE_INFO(retpoline, "Y");
#endif
#ifdef CONFIG_MPROFILE_KERNEL
	MODULE_INFO(mprofile, "Y");
#endif
