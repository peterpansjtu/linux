/*
 * Copyright 2017 ATMEL
 * Copyright 2017 Free Electrons
 *
 * Author: Boris Brezillon <boris.brezillon@free-electrons.com>
 *
 * Derived from the atmel_nand.c driver which contained the following
 * copyrights:
 *
 *   Copyright 2003 Rick Bronson
 *
 *   Derived from drivers/mtd/nand/autcpu12.c
 *	Copyright 2001 Thomas Gleixner (gleixner@autronix.de)
 *
 *   Derived from drivers/mtd/spia.c
 *	Copyright 2000 Steven J. Hill (sjhill@cotw.com)
 *
 *
 *   Add Hardware ECC support for AT91SAM9260 / AT91SAM9263
 *	Richard Genoud (richard.genoud@gmail.com), Adeneo Copyright 2007
 *
 *   Derived from Das U-Boot source code
 *	(u-boot-1.1.5/board/atmel/at91sam9263ek/nand.c)
 *	Copyright 2006 ATMEL Rousset, Lacressonniere Nicolas
 *
 *   Add Programmable Multibit ECC support for various AT91 SoC
 *	Copyright 2012 ATMEL, Hong Xu
 *
 *   Add Nand Flash Controller support for SAMA5 SoC
 *	Copyright 2013 ATMEL, Josh Wu (josh.wu@atmel.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * A few words about the naming convention in this file. This convention
 * applies to structure and function names.
 *
 * Prefixes:
 *
 * - atmel_nand_: all generic structures/functions
 * - atmel_smc_nand_: all structures/functions specific to the SMC interface
 *		      (at91sam9 and avr32 SoCs)
 * - atmel_hsmc_nand_: all structures/functions specific to the HSMC interface
 *		       (sama5 SoCs and later)
 * - atmel_nfc_: all structures/functions used to manipulate the NFC sub-block
 *		 that is available in the HSMC block
 * - <soc>_nand_: all SoC specific structures/functions
 */

#include <linux/clk.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/genalloc.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/mfd/syscon.h>
#include <linux/mfd/syscon/atmel-matrix.h>
#include <linux/module.h>
#include <linux/mtd/nand.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/iopoll.h>
#include <linux/platform_device.h>
#include <linux/platform_data/atmel.h>
#include <linux/regmap.h>

#include "pmecc.h"

#define ATMEL_HSMC_NFC_CFG			0x0
#define ATMEL_HSMC_NFC_CFG_SPARESIZE(x)		(((x) / 4) << 24)
#define ATMEL_HSMC_NFC_CFG_SPARESIZE_MASK	GENMASK(30, 24)
#define ATMEL_HSMC_NFC_CFG_DTO(cyc, mul)	(((cyc) << 16) | ((mul) << 20))
#define ATMEL_HSMC_NFC_CFG_DTO_MAX		GENMASK(22, 16)
#define ATMEL_HSMC_NFC_CFG_RBEDGE		BIT(13)
#define ATMEL_HSMC_NFC_CFG_FALLING_EDGE		BIT(12)
#define ATMEL_HSMC_NFC_CFG_RSPARE		BIT(9)
#define ATMEL_HSMC_NFC_CFG_WSPARE		BIT(8)
#define ATMEL_HSMC_NFC_CFG_PAGESIZE_MASK	GENMASK(2, 0)
#define ATMEL_HSMC_NFC_CFG_PAGESIZE(x)		(fls((x) / 512) - 1)

#define ATMEL_HSMC_NFC_CTRL			0x4
#define ATMEL_HSMC_NFC_CTRL_EN			BIT(0)
#define ATMEL_HSMC_NFC_CTRL_DIS			BIT(1)

#define ATMEL_HSMC_NFC_SR			0x8
#define ATMEL_HSMC_NFC_IER			0xc
#define ATMEL_HSMC_NFC_IDR			0x10
#define ATMEL_HSMC_NFC_IMR			0x14
#define ATMEL_HSMC_NFC_SR_ENABLED		BIT(1)
#define ATMEL_HSMC_NFC_SR_RB_RISE		BIT(4)
#define ATMEL_HSMC_NFC_SR_RB_FALL		BIT(5)
#define ATMEL_HSMC_NFC_SR_BUSY			BIT(8)
#define ATMEL_HSMC_NFC_SR_WR			BIT(11)
#define ATMEL_HSMC_NFC_SR_CSID			GENMASK(14, 12)
#define ATMEL_HSMC_NFC_SR_XFRDONE		BIT(16)
#define ATMEL_HSMC_NFC_SR_CMDDONE		BIT(17)
#define ATMEL_HSMC_NFC_SR_DTOE			BIT(20)
#define ATMEL_HSMC_NFC_SR_UNDEF			BIT(21)
#define ATMEL_HSMC_NFC_SR_AWB			BIT(22)
#define ATMEL_HSMC_NFC_SR_NFCASE		BIT(23)
#define ATMEL_HSMC_NFC_SR_ERRORS		(ATMEL_HSMC_NFC_SR_DTOE | \
						 ATMEL_HSMC_NFC_SR_UNDEF | \
						 ATMEL_HSMC_NFC_SR_AWB | \
						 ATMEL_HSMC_NFC_SR_NFCASE)
#define ATMEL_HSMC_NFC_SR_RBEDGE(x)		BIT((x) + 24)

#define ATMEL_HSMC_NFC_ADDR			0x18
#define ATMEL_HSMC_NFC_BANK			0x1c

#define ATMEL_NFC_MAX_RB_ID			7

#define ATMEL_NFC_SRAM_SIZE			0x2400

#define ATMEL_NFC_CMD(pos, cmd)			((cmd) << (((pos) * 8) + 2))
#define ATMEL_NFC_VCMD2				BIT(18)
#define ATMEL_NFC_ACYCLE(naddrs)		((naddrs) << 19)
#define ATMEL_NFC_CSID(cs)			((cs) << 22)
#define ATMEL_NFC_DATAEN			BIT(25)
#define ATMEL_NFC_NFCWR				BIT(26)

#define ATMEL_NFC_MAX_ADDR_CYCLES		5

#define ATMEL_NAND_ALE_OFFSET			BIT(21)
#define ATMEL_NAND_CLE_OFFSET			BIT(22)

#define DEFAULT_TIMEOUT_MS			1000
#define MIN_DMA_LEN				128

enum atmel_nand_rb_type {
	ATMEL_NAND_NO_RB,
	ATMEL_NAND_NATIVE_RB,
	ATMEL_NAND_GPIO_RB,
};

struct atmel_nand_rb {
	enum atmel_nand_rb_type type;
	union {
		struct gpio_desc *gpio;
		int id;
	};
};

struct atmel_nand_cs {
	int id;
	struct atmel_nand_rb rb;
	struct gpio_desc *csgpio;
	struct {
		void __iomem *virt;
		dma_addr_t dma;
	} io;
};

struct atmel_nand {
	struct list_head node;
	struct device *dev;
	struct nand_chip base;
	struct atmel_nand_cs *activecs;
	struct atmel_pmecc_user *pmecc;
	struct gpio_desc *cdgpio;
	int numcs;
	struct atmel_nand_cs cs[];
};

static inline struct atmel_nand *to_atmel_nand(struct nand_chip *chip)
{
	return container_of(chip, struct atmel_nand, base);
}

enum atmel_nfc_data_xfer {
	ATMEL_NFC_NO_DATA,
	ATMEL_NFC_READ_DATA,
	ATMEL_NFC_WRITE_DATA,
};

struct atmel_nfc_op {
	u8 cs;
	u8 ncmds;
	u8 cmds[2];
	u8 naddrs;
	u8 addrs[5];
	enum atmel_nfc_data_xfer data;
	u32 wait;
	u32 errors;
};

struct atmel_nand_controller;
struct atmel_nand_controller_caps;

struct atmel_nand_controller_ops {
	int (*probe)(struct platform_device *pdev,
		     const struct atmel_nand_controller_caps *caps);
	int (*remove)(struct atmel_nand_controller *nc);
	void (*nand_init)(struct atmel_nand_controller *nc,
			  struct atmel_nand *nand);
	int (*ecc_init)(struct atmel_nand *nand);
};

struct atmel_nand_controller_caps {
	bool has_dma;
	bool legacy_of_bindings;
	u32 ale_offs;
	u32 cle_offs;
	const struct atmel_nand_controller_ops *ops;
};

struct atmel_nand_controller {
	struct nand_hw_control base;
	const struct atmel_nand_controller_caps *caps;
	struct device *dev;
	struct regmap *smc;
	struct dma_chan *dmac;
	struct atmel_pmecc *pmecc;
	struct list_head chips;
	struct clk *mck;
};

static inline struct atmel_nand_controller *
to_nand_controller(struct nand_hw_control *ctl)
{
	return container_of(ctl, struct atmel_nand_controller, base);
}

struct atmel_smc_nand_controller {
	struct atmel_nand_controller base;
	struct regmap *matrix;
	unsigned int ebi_csa_offs;
};

static inline struct atmel_smc_nand_controller *
to_smc_nand_controller(struct nand_hw_control *ctl)
{
	return container_of(to_nand_controller(ctl),
			    struct atmel_smc_nand_controller, base);
}

struct atmel_hsmc_nand_controller {
	struct atmel_nand_controller base;
	struct {
		struct gen_pool *pool;
		void __iomem *virt;
		dma_addr_t dma;
	} sram;
	struct regmap *io;
	struct atmel_nfc_op op;
	struct completion complete;
	int irq;

	/* Only used when instantiating from legacy DT bindings. */
	struct clk *clk;
};

static inline struct atmel_hsmc_nand_controller *
to_hsmc_nand_controller(struct nand_hw_control *ctl)
{
	return container_of(to_nand_controller(ctl),
			    struct atmel_hsmc_nand_controller, base);
}

static bool atmel_nfc_op_done(struct atmel_nfc_op *op, u32 status)
{
	op->errors |= status & ATMEL_HSMC_NFC_SR_ERRORS;
	op->wait ^= status & op->wait;

	return !op->wait || op->errors;
}

static irqreturn_t atmel_nfc_interrupt(int irq, void *data)
{
	struct atmel_hsmc_nand_controller *nc = data;
	u32 sr, rcvd;
	bool done;

	regmap_read(nc->base.smc, ATMEL_HSMC_NFC_SR, &sr);

	rcvd = sr & (nc->op.wait | ATMEL_HSMC_NFC_SR_ERRORS);
	done = atmel_nfc_op_done(&nc->op, sr);

	if (rcvd)
		regmap_write(nc->base.smc, ATMEL_HSMC_NFC_IDR, rcvd);

	if (done)
		complete(&nc->complete);

	return rcvd ? IRQ_HANDLED : IRQ_NONE;
}

static int atmel_nfc_wait(struct atmel_hsmc_nand_controller *nc, bool poll,
			  unsigned int timeout_ms)
{
	int ret;

	if (!timeout_ms)
		timeout_ms = DEFAULT_TIMEOUT_MS;

	if (poll) {
		u32 status;

		ret = regmap_read_poll_timeout(nc->base.smc,
					       ATMEL_HSMC_NFC_SR, status,
					       atmel_nfc_op_done(&nc->op,
								 status),
					       0, timeout_ms * 1000);
	} else {
		init_completion(&nc->complete);
		regmap_write(nc->base.smc, ATMEL_HSMC_NFC_IER,
			     nc->op.wait | ATMEL_HSMC_NFC_SR_ERRORS);
		ret = wait_for_completion_timeout(&nc->complete,
						msecs_to_jiffies(timeout_ms));
		if (!ret)
			ret = -ETIMEDOUT;
		else
			ret = 0;

		regmap_write(nc->base.smc, ATMEL_HSMC_NFC_IDR, 0xffffffff);
	}

	if (nc->op.errors & ATMEL_HSMC_NFC_SR_DTOE) {
		dev_err(nc->base.dev, "Waiting NAND R/B Timeout\n");
		ret = -ETIMEDOUT;
	}

	if (nc->op.errors & ATMEL_HSMC_NFC_SR_UNDEF) {
		dev_err(nc->base.dev, "Access to an undefined area\n");
		ret = -EIO;
	}

	if (nc->op.errors & ATMEL_HSMC_NFC_SR_AWB) {
		dev_err(nc->base.dev, "Access while busy\n");
		ret = -EIO;
	}

	if (nc->op.errors & ATMEL_HSMC_NFC_SR_NFCASE) {
		dev_err(nc->base.dev, "Wrong access size\n");
		ret = -EIO;
	}

	return ret;
}

static void atmel_nand_dma_transfer_finished(void *data)
{
	struct completion *finished = data;

	complete(finished);
}

static int atmel_nand_dma_transfer(struct atmel_nand_controller *nc,
				   void *buf, dma_addr_t dev_dma, size_t len,
				   enum dma_data_direction dir)
{
	DECLARE_COMPLETION_ONSTACK(finished);
	dma_addr_t src_dma, dst_dma, buf_dma;
	struct dma_async_tx_descriptor *tx;
	dma_cookie_t cookie;

	buf_dma = dma_map_single(nc->dev, buf, len, dir);
	if (dma_mapping_error(nc->dev, dev_dma)) {
		dev_err(nc->dev,
			"Failed to prepare a buffer for DMA access\n");
		goto err;
	}

	if (dir == DMA_FROM_DEVICE) {
		src_dma = dev_dma;
		dst_dma = buf_dma;
	} else {
		src_dma = buf_dma;
		dst_dma = dev_dma;
	}

	tx = dmaengine_prep_dma_memcpy(nc->dmac, dst_dma, src_dma, len,
				       DMA_CTRL_ACK | DMA_PREP_INTERRUPT);
	if (!tx) {
		dev_err(nc->dev, "Failed to prepare DMA memcpy\n");
		goto err_unmap;
	}

	tx->callback = atmel_nand_dma_transfer_finished;
	tx->callback_param = &finished;

	cookie = dmaengine_submit(tx);
	if (dma_submit_error(cookie)) {
		dev_err(nc->dev, "Failed to do DMA tx_submit\n");
		goto err_unmap;
	}

	dma_async_issue_pending(nc->dmac);
	wait_for_completion(&finished);

	return 0;

err_unmap:
	dma_unmap_single(nc->dev, buf_dma, len, dir);

err:
	dev_dbg(nc->dev, "Fall back to CPU I/O\n");

	return -EIO;
}

static u8 atmel_nand_read_byte(struct mtd_info *mtd)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);

	return ioread8(nand->activecs->io.virt);
}

static u16 atmel_nand_read_word(struct mtd_info *mtd)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);

	return ioread16(nand->activecs->io.virt);
}

static void atmel_nand_write_byte(struct mtd_info *mtd, u8 byte)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);

	if (chip->options & NAND_BUSWIDTH_16)
		iowrite16(byte | (byte << 8), nand->activecs->io.virt);
	else
		iowrite8(byte, nand->activecs->io.virt);
}

static void atmel_nand_read_buf(struct mtd_info *mtd, u8 *buf, int len)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct atmel_nand_controller *nc;

	nc = to_nand_controller(chip->controller);

	/*
	 * If the controller supports DMA, the buffer address is DMA-able and
	 * len is long enough to make DMA transfers profitable, let's trigger
	 * a DMA transfer. If it fails, fallback to PIO mode.
	 */
	if (nc->dmac && virt_addr_valid(buf) &&
	    len >= MIN_DMA_LEN &&
	    !atmel_nand_dma_transfer(nc, buf, nand->activecs->io.dma, len,
				     DMA_FROM_DEVICE))
		return;

	if (chip->options & NAND_BUSWIDTH_16)
		ioread16_rep(nand->activecs->io.virt, buf, len / 2);
	else
		ioread8_rep(nand->activecs->io.virt, buf, len);
}

static void atmel_nand_write_buf(struct mtd_info *mtd, const u8 *buf, int len)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct atmel_nand_controller *nc;

	nc = to_nand_controller(chip->controller);

	/*
	 * If the controller supports DMA, the buffer address is DMA-able and
	 * len is long enough to make DMA transfers profitable, let's trigger
	 * a DMA transfer. If it fails, fallback to PIO mode.
	 */
	if (nc->dmac && virt_addr_valid(buf) &&
	    len >= MIN_DMA_LEN &&
	    !atmel_nand_dma_transfer(nc, (void *)buf, nand->activecs->io.dma,
				     len, DMA_TO_DEVICE))
		return;

	if (chip->options & NAND_BUSWIDTH_16)
		iowrite16_rep(nand->activecs->io.virt, buf, len / 2);
	else
		iowrite8_rep(nand->activecs->io.virt, buf, len);
}

static int atmel_nand_dev_ready(struct mtd_info *mtd)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);

	return gpiod_get_value(nand->activecs->rb.gpio);
}

static void atmel_nand_select_chip(struct mtd_info *mtd, int cs)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);

	if (cs < 0 || cs >= nand->numcs) {
		nand->activecs = NULL;
		chip->dev_ready = NULL;
		return;
	}

	nand->activecs = &nand->cs[cs];

	if (nand->activecs->rb.type == ATMEL_NAND_GPIO_RB)
		chip->dev_ready = atmel_nand_dev_ready;
}

static int atmel_hsmc_nand_dev_ready(struct mtd_info *mtd)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct atmel_hsmc_nand_controller *nc;
	u32 status;

	nc = to_hsmc_nand_controller(chip->controller);

	regmap_read(nc->base.smc, ATMEL_HSMC_NFC_SR, &status);

	return status & ATMEL_HSMC_NFC_SR_RBEDGE(nand->activecs->rb.id);
}

static void atmel_hsmc_nand_select_chip(struct mtd_info *mtd, int cs)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct atmel_hsmc_nand_controller *nc;

	nc = to_hsmc_nand_controller(chip->controller);

	atmel_nand_select_chip(mtd, cs);

	if (!nand->activecs) {
		regmap_write(nc->base.smc, ATMEL_HSMC_NFC_CTRL,
			     ATMEL_HSMC_NFC_CTRL_DIS);
		return;
	}

	if (nand->activecs->rb.type == ATMEL_NAND_NATIVE_RB)
		chip->dev_ready = atmel_hsmc_nand_dev_ready;

	regmap_update_bits(nc->base.smc, ATMEL_HSMC_NFC_CFG,
			   ATMEL_HSMC_NFC_CFG_PAGESIZE_MASK |
			   ATMEL_HSMC_NFC_CFG_SPARESIZE_MASK |
			   ATMEL_HSMC_NFC_CFG_RSPARE |
			   ATMEL_HSMC_NFC_CFG_WSPARE,
			   ATMEL_HSMC_NFC_CFG_PAGESIZE(mtd->writesize) |
			   ATMEL_HSMC_NFC_CFG_SPARESIZE(mtd->oobsize) |
			   ATMEL_HSMC_NFC_CFG_RSPARE);
	regmap_write(nc->base.smc, ATMEL_HSMC_NFC_CTRL,
		     ATMEL_HSMC_NFC_CTRL_EN);
}

static int atmel_nfc_exec_op(struct atmel_hsmc_nand_controller *nc, bool poll)
{
	u8 *addrs = nc->op.addrs;
	unsigned int op = 0;
	u32 addr, val;
	int i, ret;

	nc->op.wait = ATMEL_HSMC_NFC_SR_CMDDONE;

	for (i = 0; i < nc->op.ncmds; i++)
		op |= ATMEL_NFC_CMD(i, nc->op.cmds[i]);

	if (nc->op.naddrs == ATMEL_NFC_MAX_ADDR_CYCLES)
		regmap_write(nc->base.smc, ATMEL_HSMC_NFC_ADDR, *addrs++);

	op |= ATMEL_NFC_CSID(nc->op.cs) |
	      ATMEL_NFC_ACYCLE(nc->op.naddrs);

	if (nc->op.ncmds > 1)
		op |= ATMEL_NFC_VCMD2;

	addr = addrs[0] | (addrs[1] << 8) | (addrs[2] << 16) |
	       (addrs[3] << 24);

	if (nc->op.data != ATMEL_NFC_NO_DATA) {
		op |= ATMEL_NFC_DATAEN;
		nc->op.wait |= ATMEL_HSMC_NFC_SR_XFRDONE;

		if (nc->op.data == ATMEL_NFC_WRITE_DATA)
			op |= ATMEL_NFC_NFCWR;
	}

	/* Clear all flags. */
	regmap_read(nc->base.smc, ATMEL_HSMC_NFC_SR, &val);

	/* Send the command. */
	regmap_write(nc->io, op, addr);

	ret = atmel_nfc_wait(nc, poll, 0);
	if (ret)
		dev_err(nc->base.dev,
			"Failed to send NAND command (err = %d)!",
			ret);

	/* Reset the op state. */
	memset(&nc->op, 0, sizeof(nc->op));

	return ret;
}

static void atmel_hsmc_nand_cmd_ctrl(struct mtd_info *mtd, int dat,
				     unsigned int ctrl)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct atmel_hsmc_nand_controller *nc;

	nc = to_hsmc_nand_controller(chip->controller);

	if (ctrl & NAND_ALE) {
		if (nc->op.naddrs == ATMEL_NFC_MAX_ADDR_CYCLES)
			return;

		nc->op.addrs[nc->op.naddrs++] = dat;
	} else if (ctrl & NAND_CLE) {
		if (nc->op.ncmds > 1)
			return;

		nc->op.cmds[nc->op.ncmds++] = dat;
	}

	if (dat == NAND_CMD_NONE) {
		nc->op.cs = nand->activecs->id;
		atmel_nfc_exec_op(nc, true);
	}
}

static void atmel_nand_cmd_ctrl(struct mtd_info *mtd, int cmd,
				unsigned int ctrl)
{
	struct nand_chip *chip = mtd_to_nand(mtd);
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct atmel_nand_controller *nc;

	nc = to_nand_controller(chip->controller);

	if ((ctrl & NAND_CTRL_CHANGE) && nand->activecs->csgpio) {
		if (ctrl & NAND_NCE)
			gpiod_set_value(nand->activecs->csgpio, 0);
		else
			gpiod_set_value(nand->activecs->csgpio, 1);
	}

	if (ctrl & NAND_ALE)
		writeb(cmd, nand->activecs->io.virt + nc->caps->ale_offs);
	else if (ctrl & NAND_CLE)
		writeb(cmd, nand->activecs->io.virt + nc->caps->cle_offs);
}

static void atmel_nfc_copy_to_sram(struct nand_chip *chip, const u8 *buf,
				   bool oob_required)
{
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_hsmc_nand_controller *nc;
	int ret = -EIO;

	nc = to_hsmc_nand_controller(chip->controller);

	if (nc->base.dmac)
		ret = atmel_nand_dma_transfer(&nc->base, (void *)buf,
					      nc->sram.dma, mtd->writesize,
					      DMA_TO_DEVICE);

	/* Falling back to CPU copy. */
	if (ret)
		memcpy_toio(nc->sram.virt, buf, mtd->writesize);

	if (oob_required)
		memcpy_toio(nc->sram.virt + mtd->writesize, chip->oob_poi,
			    mtd->oobsize);
}

static void atmel_nfc_copy_from_sram(struct nand_chip *chip, u8 *buf,
				     bool oob_required)
{
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_hsmc_nand_controller *nc;
	int ret = -EIO;

	nc = to_hsmc_nand_controller(chip->controller);

	if (nc->base.dmac)
		ret = atmel_nand_dma_transfer(&nc->base, buf, nc->sram.dma,
					      mtd->writesize, DMA_FROM_DEVICE);

	/* Falling back to CPU copy. */
	if (ret)
		memcpy_fromio(buf, nc->sram.virt, mtd->writesize);

	if (oob_required)
		memcpy_fromio(chip->oob_poi, nc->sram.virt + mtd->writesize,
			      mtd->oobsize);
}

static void atmel_nfc_set_op_addr(struct nand_chip *chip, int page, int column)
{
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_hsmc_nand_controller *nc;

	nc = to_hsmc_nand_controller(chip->controller);

	if (column >= 0) {
		nc->op.addrs[nc->op.naddrs++] = column;

		/*
		 * 2 address cycles for the column offset on large page NANDs.
		 */
		if (mtd->writesize > 512)
			nc->op.addrs[nc->op.naddrs++] = column >> 8;
	}

	if (page >= 0) {
		nc->op.addrs[nc->op.naddrs++] = page;
		nc->op.addrs[nc->op.naddrs++] = page >> 8;

		if ((mtd->writesize > 512 && chip->chipsize > SZ_128M) ||
		    (mtd->writesize <= 512 && chip->chipsize > SZ_32M))
			nc->op.addrs[nc->op.naddrs++] = page >> 16;
	}
}

static int atmel_nand_pmecc_enable(struct nand_chip *chip, int op, bool raw)
{
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct atmel_nand_controller *nc;
	int ret;

	nc = to_nand_controller(chip->controller);

	if (raw)
		return 0;

	ret = atmel_pmecc_enable(nand->pmecc, op);
	if (ret)
		dev_err(nc->dev,
			"Failed to enable ECC engine (err = %d)\n", ret);

	return ret;
}

static void atmel_nand_pmecc_disable(struct nand_chip *chip, bool raw)
{
	struct atmel_nand *nand = to_atmel_nand(chip);

	if (!raw)
		atmel_pmecc_disable(nand->pmecc);
}

static int atmel_nand_pmecc_generate_eccbytes(struct nand_chip *chip, bool raw)
{
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_nand_controller *nc;
	struct mtd_oob_region oobregion;
	void *eccbuf;
	int ret, i;

	nc = to_nand_controller(chip->controller);

	if (raw)
		return 0;

	ret = atmel_pmecc_wait_rdy(nand->pmecc);
	if (ret) {
		dev_err(nc->dev,
			"Failed to transfer NAND page data (err = %d)\n",
			ret);
		return ret;
	}

	mtd_ooblayout_ecc(mtd, 0, &oobregion);
	eccbuf = chip->oob_poi + oobregion.offset;

	for (i = 0; i < chip->ecc.steps; i++) {
		atmel_pmecc_get_generated_eccbytes(nand->pmecc, i,
						   eccbuf);
		eccbuf += chip->ecc.bytes;
	}

	return 0;
}

static int atmel_nand_pmecc_correct_data(struct nand_chip *chip, void *buf,
					 bool raw)
{
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_nand_controller *nc;
	struct mtd_oob_region oobregion;
	int ret, i, max_bitflips = 0;
	void *databuf, *eccbuf;

	nc = to_nand_controller(chip->controller);

	if (raw)
		return 0;

	ret = atmel_pmecc_wait_rdy(nand->pmecc);
	if (ret) {
		dev_err(nc->dev,
			"Failed to read NAND page data (err = %d)\n",
			ret);
		return ret;
	}

	mtd_ooblayout_ecc(mtd, 0, &oobregion);
	eccbuf = chip->oob_poi + oobregion.offset;
	databuf = buf;

	for (i = 0; i < chip->ecc.steps; i++) {
		ret = atmel_pmecc_correct_sector(nand->pmecc, i, databuf,
						 eccbuf);
		if (ret < 0 && !atmel_pmecc_correct_erased_chunks(nand->pmecc))
			ret = nand_check_erased_ecc_chunk(databuf,
							  chip->ecc.size,
							  eccbuf,
							  chip->ecc.bytes,
							  NULL, 0,
							  chip->ecc.strength);

		if (ret >= 0)
			max_bitflips = max(ret, max_bitflips);
		else
			mtd->ecc_stats.failed++;

		databuf += chip->ecc.size;
		eccbuf += chip->ecc.bytes;
	}

	return max_bitflips;
}

static int atmel_nand_pmecc_write_pg(struct nand_chip *chip, const u8 *buf,
				     bool oob_required, int page, bool raw)
{
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_nand *nand = to_atmel_nand(chip);
	int ret;

	ret = atmel_nand_pmecc_enable(chip, NAND_ECC_WRITE, raw);
	if (ret)
		return ret;

	atmel_nand_write_buf(mtd, buf, mtd->writesize);

	ret = atmel_nand_pmecc_generate_eccbytes(chip, raw);
	if (ret) {
		atmel_pmecc_disable(nand->pmecc);
		return ret;
	}

	atmel_nand_pmecc_disable(chip, raw);

	atmel_nand_write_buf(mtd, chip->oob_poi, mtd->oobsize);

	return 0;
}

static int atmel_nand_pmecc_write_page(struct mtd_info *mtd,
				       struct nand_chip *chip, const u8 *buf,
				       int oob_required, int page)
{
	return atmel_nand_pmecc_write_pg(chip, buf, oob_required, page, false);
}

static int atmel_nand_pmecc_write_page_raw(struct mtd_info *mtd,
					   struct nand_chip *chip,
					   const u8 *buf, int oob_required,
					   int page)
{
	return atmel_nand_pmecc_write_pg(chip, buf, oob_required, page, true);
}

static int atmel_nand_pmecc_read_pg(struct nand_chip *chip, u8 *buf,
				    bool oob_required, int page, bool raw)
{
	struct mtd_info *mtd = nand_to_mtd(chip);
	int ret;

	ret = atmel_nand_pmecc_enable(chip, NAND_ECC_READ, raw);
	if (ret)
		return ret;

	atmel_nand_read_buf(mtd, buf, mtd->writesize);
	atmel_nand_read_buf(mtd, chip->oob_poi, mtd->oobsize);

	ret = atmel_nand_pmecc_correct_data(chip, buf, raw);

	atmel_nand_pmecc_disable(chip, raw);

	return ret;
}

static int atmel_nand_pmecc_read_page(struct mtd_info *mtd,
				      struct nand_chip *chip, u8 *buf,
				      int oob_required, int page)
{
	return atmel_nand_pmecc_read_pg(chip, buf, oob_required, page, false);
}

static int atmel_nand_pmecc_read_page_raw(struct mtd_info *mtd,
					  struct nand_chip *chip, u8 *buf,
					  int oob_required, int page)
{
	return atmel_nand_pmecc_read_pg(chip, buf, oob_required, page, true);
}

static int atmel_hsmc_nand_pmecc_write_pg(struct nand_chip *chip,
					  const u8 *buf, bool oob_required,
					  int page, bool raw)
{
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct atmel_hsmc_nand_controller *nc;
	int ret;

	nc = to_hsmc_nand_controller(chip->controller);

	atmel_nfc_copy_to_sram(chip, buf, false);

	nc->op.cmds[0] = NAND_CMD_SEQIN;
	nc->op.ncmds = 1;
	atmel_nfc_set_op_addr(chip, page, 0x0);
	nc->op.cs = nand->activecs->id;
	nc->op.data = ATMEL_NFC_WRITE_DATA;

	ret = atmel_nand_pmecc_enable(chip, NAND_ECC_WRITE, raw);
	if (ret)
		return ret;

	ret = atmel_nfc_exec_op(nc, false);
	if (ret) {
		atmel_nand_pmecc_disable(chip, raw);
		dev_err(nc->base.dev,
			"Failed to transfer NAND page data (err = %d)\n",
			ret);
		return ret;
	}

	ret = atmel_nand_pmecc_generate_eccbytes(chip, raw);

	atmel_nand_pmecc_disable(chip, raw);

	if (ret)
		return ret;

	atmel_nand_write_buf(mtd, chip->oob_poi, mtd->oobsize);

	nc->op.cmds[0] = NAND_CMD_PAGEPROG;
	nc->op.ncmds = 1;
	nc->op.cs = nand->activecs->id;
	ret = atmel_nfc_exec_op(nc, false);
	if (ret)
		dev_err(nc->base.dev, "Failed to program NAND page (err = %d)\n",
			ret);

	return ret;
}

static int atmel_hsmc_nand_pmecc_write_page(struct mtd_info *mtd,
					    struct nand_chip *chip,
					    const u8 *buf, int oob_required,
					    int page)
{
	return atmel_hsmc_nand_pmecc_write_pg(chip, buf, oob_required, page,
					      false);
}

static int atmel_hsmc_nand_pmecc_write_page_raw(struct mtd_info *mtd,
						struct nand_chip *chip,
						const u8 *buf,
						int oob_required, int page)
{
	return atmel_hsmc_nand_pmecc_write_pg(chip, buf, oob_required, page,
					      true);
}

static int atmel_hsmc_nand_pmecc_read_pg(struct nand_chip *chip, u8 *buf,
					 bool oob_required, int page,
					 bool raw)
{
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct atmel_hsmc_nand_controller *nc;
	int ret;

	nc = to_hsmc_nand_controller(chip->controller);

	/*
	 * Optimized read page accessors only work when the NAND R/B pin is
	 * connected to a native SoC R/B pin. If that's not the case, fallback
	 * to the non-optimized one.
	 */
	if (nand->activecs->rb.type != ATMEL_NAND_NATIVE_RB) {
		chip->cmdfunc(mtd, NAND_CMD_READ0, 0x00, page);

		return atmel_nand_pmecc_read_pg(chip, buf, oob_required, page,
						raw);
	}

	nc->op.cmds[nc->op.ncmds++] = NAND_CMD_READ0;

	if (mtd->writesize > 512)
		nc->op.cmds[nc->op.ncmds++] = NAND_CMD_READSTART;

	atmel_nfc_set_op_addr(chip, page, 0x0);
	nc->op.cs = nand->activecs->id;
	nc->op.data = ATMEL_NFC_READ_DATA;

	ret = atmel_nand_pmecc_enable(chip, NAND_ECC_READ, raw);
	if (ret)
		return ret;

	ret = atmel_nfc_exec_op(nc, false);
	if (ret) {
		atmel_nand_pmecc_disable(chip, raw);
		dev_err(nc->base.dev,
			"Failed to load NAND page data (err = %d)\n",
			ret);
		return ret;
	}

	atmel_nfc_copy_from_sram(chip, buf, true);

	ret = atmel_nand_pmecc_correct_data(chip, buf, raw);

	atmel_nand_pmecc_disable(chip, raw);

	return ret;
}

static int atmel_hsmc_nand_pmecc_read_page(struct mtd_info *mtd,
					   struct nand_chip *chip, u8 *buf,
					   int oob_required, int page)
{
	return atmel_hsmc_nand_pmecc_read_pg(chip, buf, oob_required, page,
					     false);
}

static int atmel_hsmc_nand_pmecc_read_page_raw(struct mtd_info *mtd,
					       struct nand_chip *chip,
					       u8 *buf, int oob_required,
					       int page)
{
	return atmel_hsmc_nand_pmecc_read_pg(chip, buf, oob_required, page,
					     true);
}

static int atmel_nand_pmecc_init(struct nand_chip *chip)
{
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_nand *nand = to_atmel_nand(chip);
	struct atmel_nand_controller *nc;
	struct atmel_pmecc_user_req req;

	nc = to_nand_controller(chip->controller);

	if (!nc->pmecc) {
		dev_err(nc->dev, "HW ECC not supported\n");
		return -ENOTSUPP;
	}

	if (nc->caps->legacy_of_bindings) {
		u32 val;

		if (!of_property_read_u32(nc->dev->of_node, "atmel,pmecc-cap",
					  &val))
			chip->ecc.strength = val;

		if (!of_property_read_u32(nc->dev->of_node,
					  "atmel,pmecc-sector-size",
					  &val))
			chip->ecc.size = val;
	}

	if (chip->ecc.options & NAND_ECC_MAXIMIZE)
		req.ecc.strength = ATMEL_PMECC_MAXIMIZE_ECC_STRENGTH;
	else if (chip->ecc.strength)
		req.ecc.strength = chip->ecc.strength;
	else if (chip->ecc_strength_ds)
		req.ecc.strength = chip->ecc_strength_ds;
	else
		req.ecc.strength = ATMEL_PMECC_MAXIMIZE_ECC_STRENGTH;

	if (chip->ecc.size)
		req.ecc.sectorsize = chip->ecc.size;
	else if (chip->ecc_step_ds)
		req.ecc.sectorsize = chip->ecc_step_ds;
	else
		req.ecc.sectorsize = ATMEL_PMECC_SECTOR_SIZE_AUTO;

	req.pagesize = mtd->writesize;
	req.oobsize = mtd->oobsize;

	if (mtd->writesize <= 512) {
		req.ecc.bytes = 4;
		req.ecc.ooboffset = 0;
	} else {
		req.ecc.bytes = mtd->oobsize - 2;
		req.ecc.ooboffset = ATMEL_PMECC_OOBOFFSET_AUTO;
	}

	nand->pmecc = atmel_pmecc_create_user(nc->pmecc, &req);
	if (IS_ERR(nand->pmecc))
		return PTR_ERR(nand->pmecc);

	chip->ecc.algo = NAND_ECC_BCH;
	chip->ecc.size = req.ecc.sectorsize;
	chip->ecc.bytes = req.ecc.bytes / req.ecc.nsectors;
	chip->ecc.strength = req.ecc.strength;

	chip->options |= NAND_NO_SUBPAGE_WRITE;

	mtd_set_ooblayout(mtd, &nand_ooblayout_lp_ops);

	return 0;
}

static int atmel_nand_ecc_init(struct atmel_nand *nand)
{
	struct nand_chip *chip = &nand->base;
	struct atmel_nand_controller *nc;
	int ret;

	nc = to_nand_controller(chip->controller);

	switch (chip->ecc.mode) {
	case NAND_ECC_NONE:
	case NAND_ECC_SOFT:
		/*
		 * Nothing to do, the core will initialize everything for us.
		 */
		break;

	case NAND_ECC_HW:
		ret = atmel_nand_pmecc_init(chip);
		if (ret)
			return ret;

		chip->ecc.read_page = atmel_nand_pmecc_read_page;
		chip->ecc.write_page = atmel_nand_pmecc_write_page;
		chip->ecc.read_page_raw = atmel_nand_pmecc_read_page_raw;
		chip->ecc.write_page_raw = atmel_nand_pmecc_write_page_raw;
		break;

	default:
		/* Other modes are not supported. */
		dev_err(nc->dev, "Unsupported ECC mode: %d\n",
			chip->ecc.mode);
		return -ENOTSUPP;
	}

	return 0;
}

static int atmel_hsmc_nand_ecc_init(struct atmel_nand *nand)
{
	struct nand_chip *chip = &nand->base;
	int ret;

	ret = atmel_nand_ecc_init(nand);
	if (ret)
		return ret;

	if (chip->ecc.mode != NAND_ECC_HW)
		return 0;

	/* Adjust the ECC operations for the HSMC IP. */
	chip->ecc.read_page = atmel_hsmc_nand_pmecc_read_page;
	chip->ecc.write_page = atmel_hsmc_nand_pmecc_write_page;
	chip->ecc.read_page_raw = atmel_hsmc_nand_pmecc_read_page_raw;
	chip->ecc.write_page_raw = atmel_hsmc_nand_pmecc_write_page_raw;
	chip->ecc.options |= NAND_ECC_CUSTOM_PAGE_ACCESS;

	return 0;
}

static void atmel_nand_init(struct atmel_nand_controller *nc,
			    struct atmel_nand *nand)
{
	struct nand_chip *chip = &nand->base;
	struct mtd_info *mtd = nand_to_mtd(chip);

	mtd->dev.parent = nc->dev;
	nand->base.controller = &nc->base;

	chip->cmd_ctrl = atmel_nand_cmd_ctrl;
	chip->read_byte = atmel_nand_read_byte;
	chip->read_word = atmel_nand_read_word;
	chip->write_byte = atmel_nand_write_byte;
	chip->read_buf = atmel_nand_read_buf;
	chip->write_buf = atmel_nand_write_buf;
	chip->select_chip = atmel_nand_select_chip;

	/* Some NANDs require a longer delay than the default one (20us). */
	chip->chip_delay = 40;

	/*
	 * Use a bounce buffer when the buffer passed by the MTD user is not
	 * suitable for DMA.
	 */
	if (nc->dmac)
		chip->options |= NAND_USE_BOUNCE_BUFFER;

	/* Default to HW ECC if pmecc is available. */
	if (nc->pmecc)
		chip->ecc.mode = NAND_ECC_HW;
}

static void atmel_smc_nand_init(struct atmel_nand_controller *nc,
				struct atmel_nand *nand)
{
	struct nand_chip *chip = &nand->base;
	struct atmel_smc_nand_controller *smc_nc;
	int i;

	smc_nc = to_smc_nand_controller(chip->controller);

	atmel_nand_init(nc, nand);

	if (!smc_nc->matrix)
		return;

	/* Attach the CS to the NAND Flash logic. */
	for (i = 0; i < nand->numcs; i++)
		regmap_update_bits(smc_nc->matrix, smc_nc->ebi_csa_offs,
				   BIT(nand->cs[i].id), BIT(nand->cs[i].id));
}

static void atmel_hsmc_nand_init(struct atmel_nand_controller *nc,
				 struct atmel_nand *nand)
{
	struct nand_chip *chip = &nand->base;

	atmel_nand_init(nc, nand);

	/* Overload some methods for the HSMC controller. */
	chip->cmd_ctrl = atmel_hsmc_nand_cmd_ctrl;
	chip->select_chip = atmel_hsmc_nand_select_chip;
}

static int atmel_nand_detect(struct atmel_nand *nand)
{
	struct nand_chip *chip = &nand->base;
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_nand_controller *nc;
	int ret;

	nc = to_nand_controller(chip->controller);

	ret = nand_scan_ident(mtd, nand->numcs, NULL);
	if (ret)
		dev_err(nc->dev, "nand_scan_ident() failed: %d\n", ret);

	return ret;
}

static int atmel_nand_unregister(struct atmel_nand *nand)
{
	struct nand_chip *chip = &nand->base;
	struct mtd_info *mtd = nand_to_mtd(chip);
	int ret;

	ret = mtd_device_unregister(mtd);
	if (ret)
		return ret;

	nand_cleanup(chip);
	list_del(&nand->node);

	return 0;
}

static int atmel_nand_register(struct atmel_nand *nand)
{
	struct nand_chip *chip = &nand->base;
	struct mtd_info *mtd = nand_to_mtd(chip);
	struct atmel_nand_controller *nc;
	int ret;

	nc = to_nand_controller(chip->controller);

	if (nc->caps->legacy_of_bindings || !nc->dev->of_node) {
		/*
		 * We keep the MTD name unchanged to avoid breaking platforms
		 * where the MTD cmdline parser is used and the bootloader
		 * has not been updated to use the new naming scheme.
		 */
		mtd->name = "atmel_nand";
	} else if (!mtd->name) {
		/*
		 * If the new bindings are used and the bootloader has not been
		 * updated to pass a new mtdparts parameter on the cmdline, you
		 * should define the following property in your nand node:
		 *
		 *	label = "atmel_nand";
		 *
		 * This way, mtd->name will be set by the core when
		 * nand_set_flash_node() is called.
		 */
		mtd->name = devm_kasprintf(nc->dev, GFP_KERNEL,
					   "%s:nand.%d", dev_name(nc->dev),
					   nand->cs[0].id);
		if (!mtd->name) {
			dev_err(nc->dev, "Failed to allocate mtd->name\n");
			return -ENOMEM;
		}
	}

	ret = nand_scan_tail(mtd);
	if (ret) {
		dev_err(nc->dev, "nand_scan_tail() failed: %d\n", ret);
		return ret;
	}

	ret = mtd_device_register(mtd, NULL, 0);
	if (ret) {
		dev_err(nc->dev, "Failed to register mtd device: %d\n", ret);
		nand_cleanup(chip);
		return ret;
	}

	list_add_tail(&nand->node, &nc->chips);

	return 0;
}

static struct atmel_nand *atmel_nand_create(struct atmel_nand_controller *nc,
					    struct device_node *np,
					    int reg_cells)
{
	struct atmel_nand *nand;
	struct gpio_desc *gpio;
	int numcs, ret, i;

	numcs = of_property_count_elems_of_size(np, "reg",
						reg_cells * sizeof(u32));
	if (numcs < 1) {
		dev_err(nc->dev, "Missing or invalid reg property\n");
		return ERR_PTR(-EINVAL);
	}

	nand = devm_kzalloc(nc->dev,
			    sizeof(*nand) + (numcs * sizeof(*nand->cs)),
			    GFP_KERNEL);
	if (!nand) {
		dev_err(nc->dev, "Failed to allocate NAND object\n");
		return ERR_PTR(-ENOMEM);
	}

	nand->numcs = numcs;

	gpio = devm_fwnode_get_index_gpiod_from_child(nc->dev, "det", 0,
						      &np->fwnode, GPIOD_IN,
						      "nand-det");
	if (IS_ERR(gpio) && PTR_ERR(gpio) != -ENOENT) {
		dev_err(nc->dev,
			"Failed to get detect gpio (err = %ld)\n",
			PTR_ERR(gpio));
		return ERR_CAST(gpio);
	}

	if (!IS_ERR(gpio))
		nand->cdgpio = gpio;

	for (i = 0; i < numcs; i++) {
		struct resource res;
		u32 val;

		ret = of_address_to_resource(np, 0, &res);
		if (ret) {
			dev_err(nc->dev, "Invalid reg property (err = %d)\n",
				ret);
			return ERR_PTR(ret);
		}

		ret = of_property_read_u32_index(np, "reg", i * reg_cells,
						 &val);
		if (ret) {
			dev_err(nc->dev, "Invalid reg property (err = %d)\n",
				ret);
			return ERR_PTR(ret);
		}

		nand->cs[i].id = val;

		nand->cs[i].io.dma = res.start;
		nand->cs[i].io.virt = devm_ioremap_resource(nc->dev, &res);
		if (IS_ERR(nand->cs[i].io.virt))
			return ERR_CAST(nand->cs[i].io.virt);

		if (!of_property_read_u32(np, "atmel,rb", &val)) {
			if (val > ATMEL_NFC_MAX_RB_ID)
				return ERR_PTR(-EINVAL);

			nand->cs[i].rb.type = ATMEL_NAND_NATIVE_RB;
			nand->cs[i].rb.id = val;
		} else {
			gpio = devm_fwnode_get_index_gpiod_from_child(nc->dev,
							"rb", i, &np->fwnode,
							GPIOD_IN, "nand-rb");
			if (IS_ERR(gpio) && PTR_ERR(gpio) != -ENOENT) {
				dev_err(nc->dev,
					"Failed to get R/B gpio (err = %ld)\n",
					PTR_ERR(gpio));
				return ERR_CAST(gpio);
			}

			if (!IS_ERR(gpio)) {
				nand->cs[i].rb.type = ATMEL_NAND_GPIO_RB;
				nand->cs[i].rb.gpio = gpio;
			}
		}

		gpio = devm_fwnode_get_index_gpiod_from_child(nc->dev, "cs",
							      i, &np->fwnode,
							      GPIOD_OUT_HIGH,
							      "nand-cs");
		if (IS_ERR(gpio) && PTR_ERR(gpio) != -ENOENT) {
			dev_err(nc->dev,
				"Failed to get CS gpio (err = %ld)\n",
				PTR_ERR(gpio));
			return ERR_CAST(gpio);
		}

		if (!IS_ERR(gpio))
			nand->cs[i].csgpio = gpio;
	}

	nand_set_flash_node(&nand->base, np);

	return nand;
}

static int
atmel_nand_controller_add_nand(struct atmel_nand_controller *nc,
			       struct atmel_nand *nand)
{
	int ret;

	/* No card inserted, skip this NAND. */
	if (nand->cdgpio && gpiod_get_value(nand->cdgpio)) {
		dev_info(nc->dev, "No SmartMedia card inserted.\n");
		return 0;
	}

	nc->caps->ops->nand_init(nc, nand);

	ret = atmel_nand_detect(nand);
	if (ret)
		return ret;

	ret = nc->caps->ops->ecc_init(nand);
	if (ret)
		return ret;

	return atmel_nand_register(nand);
}

static int
atmel_nand_controller_remove_nands(struct atmel_nand_controller *nc)
{
	struct atmel_nand *nand, *tmp;
	int ret;

	list_for_each_entry_safe(nand, tmp, &nc->chips, node) {
		ret = atmel_nand_unregister(nand);
		if (ret)
			return ret;
	}

	return 0;
}

static int
atmel_nand_controller_legacy_add_nands(struct atmel_nand_controller *nc)
{
	struct device *dev = nc->dev;
	struct platform_device *pdev = to_platform_device(dev);
	struct atmel_nand *nand;
	struct gpio_desc *gpio;
	struct resource *res;

	/*
	 * Legacy bindings only allow connecting a single NAND with a unique CS
	 * line to the controller.
	 */
	nand = devm_kzalloc(nc->dev, sizeof(*nand) + sizeof(*nand->cs),
			    GFP_KERNEL);
	if (!nand)
		return -ENOMEM;

	nand->numcs = 1;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	nand->cs[0].io.virt = devm_ioremap_resource(dev, res);
	if (IS_ERR(nand->cs[0].io.virt))
		return PTR_ERR(nand->cs[0].io.virt);

	nand->cs[0].io.dma = res->start;

	/*
	 * The old driver was hardcoding the CS id to 3 for all sama5
	 * controllers. Since this id is only meaningful for the sama5
	 * controller we can safely assign this id to 3 no matter the
	 * controller.
	 * If one wants to connect a NAND to a different CS line, he will
	 * have to use the new bindings.
	 */
	nand->cs[0].id = 3;

	/* R/B GPIO. */
	gpio = devm_gpiod_get_index_optional(dev, NULL, 0,  GPIOD_IN);
	if (IS_ERR(gpio)) {
		dev_err(dev, "Failed to get R/B gpio (err = %ld)\n",
			PTR_ERR(gpio));
		return PTR_ERR(gpio);
	}

	if (gpio) {
		nand->cs[0].rb.type = ATMEL_NAND_GPIO_RB;
		nand->cs[0].rb.gpio = gpio;
	}

	/* CS GPIO. */
	gpio = devm_gpiod_get_index_optional(dev, NULL, 1, GPIOD_OUT_HIGH);
	if (IS_ERR(gpio)) {
		dev_err(dev, "Failed to get CS gpio (err = %ld)\n",
			PTR_ERR(gpio));
		return PTR_ERR(gpio);
	}

	nand->cs[0].csgpio = gpio;

	/* Card detect GPIO. */
	gpio = devm_gpiod_get_index_optional(nc->dev, NULL, 2, GPIOD_IN);
	if (IS_ERR(gpio)) {
		dev_err(dev,
			"Failed to get detect gpio (err = %ld)\n",
			PTR_ERR(gpio));
		return PTR_ERR(gpio);
	}

	nand->cdgpio = gpio;

	nand_set_flash_node(&nand->base, nc->dev->of_node);

	return atmel_nand_controller_add_nand(nc, nand);
}

static int atmel_nand_controller_add_nands(struct atmel_nand_controller *nc)
{
	struct device_node *np, *nand_np;
	struct device *dev = nc->dev;
	int ret, reg_cells;
	u32 val;

	/* We do not retrieve the SMC syscon when parsing old DTs. */
	if (nc->caps->legacy_of_bindings)
		return atmel_nand_controller_legacy_add_nands(nc);

	np = dev->of_node;

	ret = of_property_read_u32(np, "#address-cells", &val);
	if (ret) {
		dev_err(dev, "missing #address-cells property\n");
		return ret;
	}

	reg_cells = val;

	ret = of_property_read_u32(np, "#size-cells", &val);
	if (ret) {
		dev_err(dev, "missing #address-cells property\n");
		return ret;
	}

	reg_cells += val;

	for_each_child_of_node(np, nand_np) {
		struct atmel_nand *nand;

		nand = atmel_nand_create(nc, nand_np, reg_cells);
		if (IS_ERR(nand)) {
			ret = PTR_ERR(nand);
			goto err;
		}

		ret = atmel_nand_controller_add_nand(nc, nand);
		if (ret)
			goto err;
	}

	return 0;

err:
	atmel_nand_controller_remove_nands(nc);

	return ret;
}

static void atmel_nand_controller_cleanup(struct atmel_nand_controller *nc)
{
	if (nc->dmac)
		dma_release_channel(nc->dmac);

	clk_put(nc->mck);
}

static const struct of_device_id atmel_matrix_of_ids[] = {
	{
		.compatible = "atmel,at91sam9260-matrix",
		.data = (void *)AT91SAM9260_MATRIX_EBICSA,
	},
	{
		.compatible = "atmel,at91sam9261-matrix",
		.data = (void *)AT91SAM9261_MATRIX_EBICSA,
	},
	{
		.compatible = "atmel,at91sam9263-matrix",
		.data = (void *)AT91SAM9263_MATRIX_EBI0CSA,
	},
	{
		.compatible = "atmel,at91sam9rl-matrix",
		.data = (void *)AT91SAM9RL_MATRIX_EBICSA,
	},
	{
		.compatible = "atmel,at91sam9g45-matrix",
		.data = (void *)AT91SAM9G45_MATRIX_EBICSA,
	},
	{
		.compatible = "atmel,at91sam9n12-matrix",
		.data = (void *)AT91SAM9N12_MATRIX_EBICSA,
	},
	{
		.compatible = "atmel,at91sam9x5-matrix",
		.data = (void *)AT91SAM9X5_MATRIX_EBICSA,
	},
};

static int atmel_nand_controller_init(struct atmel_nand_controller *nc,
				struct platform_device *pdev,
				const struct atmel_nand_controller_caps *caps)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	int ret;

	nand_hw_control_init(&nc->base);
	INIT_LIST_HEAD(&nc->chips);
	nc->dev = dev;
	nc->caps = caps;

	platform_set_drvdata(pdev, nc);

	nc->pmecc = devm_atmel_pmecc_get(dev);
	if (IS_ERR(nc->pmecc)) {
		ret = PTR_ERR(nc->pmecc);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "Could not get PMECC object (err = %d)\n",
				ret);
		return ret;
	}

	if (nc->caps->has_dma) {
		dma_cap_mask_t mask;

		dma_cap_zero(mask);
		dma_cap_set(DMA_MEMCPY, mask);

		nc->dmac = dma_request_channel(mask, NULL, NULL);
		if (!nc->dmac)
			dev_err(nc->dev, "Failed to request DMA channel\n");
	}

	/* We do not retrieve the SMC syscon when parsing old DTs. */
	if (nc->caps->legacy_of_bindings)
		return 0;

	np = of_parse_phandle(dev->parent->of_node, "atmel,smc", 0);
	if (!np) {
		dev_err(dev, "Missing or invalid atmel,smc property\n");
		return -EINVAL;
	}

	nc->smc = syscon_node_to_regmap(np);
	of_node_put(np);
	if (IS_ERR(nc->smc)) {
		ret = IS_ERR(nc->smc);
		dev_err(dev, "Could not get SMC regmap (err = %d)\n", ret);
		return ret;
	}

	return 0;
}

static int
atmel_smc_nand_controller_init(struct atmel_smc_nand_controller *nc)
{
	struct device *dev = nc->base.dev;
	const struct of_device_id *match;
	struct device_node *np;
	int ret;

	/* We do not retrieve the matrix syscon when parsing old DTs. */
	if (nc->base.caps->legacy_of_bindings)
		return 0;

	np = of_parse_phandle(dev->parent->of_node, "atmel,matrix", 0);
	if (!np)
		return 0;

	match = of_match_node(atmel_matrix_of_ids, np);
	if (!match) {
		of_node_put(np);
		return 0;
	}

	nc->matrix = syscon_node_to_regmap(np);
	of_node_put(np);
	if (IS_ERR(nc->matrix)) {
		ret = IS_ERR(nc->matrix);
		dev_err(dev, "Could not get Matrix regmap (err = %d)\n", ret);
		return ret;
	}

	nc->ebi_csa_offs = (unsigned int)match->data;

	/*
	 * The at91sam9263 has 2 EBIs, if the NAND controller is under EBI1
	 * add 4 to ->ebi_csa_offs.
	 */
	if (of_device_is_compatible(dev->parent->of_node,
				    "atmel,at91sam9263-ebi1"))
		nc->ebi_csa_offs += 4;

	return 0;
}

static int
atmel_hsmc_nand_controller_legacy_init(struct atmel_hsmc_nand_controller *nc)
{
	struct regmap_config regmap_conf = {
		.reg_bits = 32,
		.val_bits = 32,
		.reg_stride = 4,
		.val_bits = 32,
	};

	struct device *dev = nc->base.dev;
	struct device_node *nand_np, *nfc_np;
	void __iomem *iomem;
	struct resource res;
	int ret;

	nand_np = dev->of_node;
	nfc_np = of_find_compatible_node(dev->of_node, NULL,
					 "atmel,sama5d3-nfc");

	nc->clk = of_clk_get(nfc_np, 0);
	if (IS_ERR(nc->clk)) {
		ret = PTR_ERR(nc->clk);
		dev_err(dev, "Failed to retrieve HSMC clock (err = %d)\n",
			ret);
		goto out;
	}

	ret = clk_prepare_enable(nc->clk);
	if (ret) {
		dev_err(dev, "Failed to enable the HSMC clock (err = %d)\n",
			ret);
		goto out;
	}

	nc->irq = of_irq_get(nand_np, 0);
	if (nc->irq < 0) {
		ret = nc->irq;
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "Failed to get IRQ number (err = %d)\n",
				ret);
		goto out;
	}

	ret = of_address_to_resource(nfc_np, 0, &res);
	if (ret) {
		dev_err(dev, "Invalid or missing NFC IO resource (err = %d)\n",
			ret);
		goto out;
	}

	iomem = devm_ioremap_resource(dev, &res);
	if (IS_ERR(iomem)) {
		ret = PTR_ERR(iomem);
		goto out;
	}

	regmap_conf.name = "nfc-io";
	regmap_conf.max_register = resource_size(&res) - 4;
	nc->io = devm_regmap_init_mmio(dev, iomem, &regmap_conf);
	if (IS_ERR(nc->io)) {
		ret = PTR_ERR(nc->io);
		dev_err(dev, "Could not create NFC IO regmap (err = %d)\n",
			ret);
		goto out;
	}

	ret = of_address_to_resource(nfc_np, 1, &res);
	if (ret) {
		dev_err(dev, "Invalid or missing HSMC resource (err = %d)\n",
			ret);
		goto out;
	}

	iomem = devm_ioremap_resource(dev, &res);
	if (IS_ERR(iomem)) {
		ret = PTR_ERR(iomem);
		goto out;
	}

	regmap_conf.name = "smc";
	regmap_conf.max_register = resource_size(&res) - 4;
	nc->base.smc = devm_regmap_init_mmio(dev, iomem, &regmap_conf);
	if (IS_ERR(nc->base.smc)) {
		ret = PTR_ERR(nc->base.smc);
		dev_err(dev, "Could not create NFC IO regmap (err = %d)\n",
			ret);
		goto out;
	}

	ret = of_address_to_resource(nfc_np, 2, &res);
	if (ret) {
		dev_err(dev, "Invalid or missing SRAM resource (err = %d)\n",
			ret);
		goto out;
	}

	nc->sram.virt = devm_ioremap_resource(dev, &res);
	if (IS_ERR(nc->sram.virt)) {
		ret = PTR_ERR(nc->sram.virt);
		goto out;
	}

	nc->sram.dma = res.start;

out:
	of_node_put(nfc_np);

	return ret;
}

static int
atmel_hsmc_nand_controller_init(struct atmel_hsmc_nand_controller *nc)
{
	struct device *dev = nc->base.dev;
	struct device_node *np;
	int ret;

	np = of_parse_phandle(dev->parent->of_node, "atmel,smc", 0);
	if (!np) {
		dev_err(dev, "Missing or invalid atmel,smc property\n");
		return -EINVAL;
	}

	nc->irq = of_irq_get(np, 0);
	of_node_put(np);
	if (nc->irq < 0) {
		if (nc->irq != -EPROBE_DEFER)
			dev_err(dev, "Failed to get IRQ number (err = %d)\n",
				nc->irq);
		return nc->irq;
	}

	np = of_parse_phandle(dev->of_node, "atmel,nfc-io", 0);
	if (!np) {
		dev_err(dev, "Missing or invalid atmel,nfc-io property\n");
		return -EINVAL;
	}

	nc->io = syscon_node_to_regmap(np);
	of_node_put(np);
	if (IS_ERR(nc->io)) {
		ret = PTR_ERR(nc->io);
		dev_err(dev, "Could not get NFC IO regmap (err = %d)\n", ret);
		return ret;
	}

	nc->sram.pool = of_gen_pool_get(nc->base.dev->of_node,
					 "atmel,nfc-sram", 0);
	if (!nc->sram.pool) {
		dev_err(nc->base.dev, "Missing SRAM\n");
		return -ENOMEM;
	}

	nc->sram.virt = gen_pool_dma_alloc(nc->sram.pool,
					    ATMEL_NFC_SRAM_SIZE,
					    &nc->sram.dma);
	if (!nc->sram.virt) {
		dev_err(nc->base.dev,
			"Could not allocate memory from the NFC SRAM pool\n");
		return -ENOMEM;
	}

	return 0;
}

static int
atmel_hsmc_nand_controller_remove(struct atmel_nand_controller *nc)
{
	struct atmel_hsmc_nand_controller *hsmc_nc;
	int ret;

	ret = atmel_nand_controller_remove_nands(nc);
	if (ret)
		return ret;

	hsmc_nc = container_of(nc, struct atmel_hsmc_nand_controller, base);
	if (hsmc_nc->sram.pool)
		gen_pool_free(hsmc_nc->sram.pool,
			      (unsigned long)hsmc_nc->sram.virt,
			      ATMEL_NFC_SRAM_SIZE);

	if (hsmc_nc->clk) {
		clk_disable_unprepare(hsmc_nc->clk);
		clk_put(hsmc_nc->clk);
	}

	atmel_nand_controller_cleanup(nc);

	return 0;
}

static int atmel_hsmc_nand_controller_probe(struct platform_device *pdev,
				const struct atmel_nand_controller_caps *caps)
{
	struct device *dev = &pdev->dev;
	struct atmel_hsmc_nand_controller *nc;
	int ret;

	nc = devm_kzalloc(dev, sizeof(*nc), GFP_KERNEL);
	if (!nc)
		return -ENOMEM;

	ret = atmel_nand_controller_init(&nc->base, pdev, caps);
	if (ret)
		return ret;

	if (caps->legacy_of_bindings)
		ret = atmel_hsmc_nand_controller_legacy_init(nc);
	else
		ret = atmel_hsmc_nand_controller_init(nc);

	if (ret)
		return ret;

	/* Make sure all irqs are masked before registering our IRQ handler. */
	regmap_write(nc->base.smc, ATMEL_HSMC_NFC_IDR, 0xffffffff);
	ret = devm_request_irq(dev, nc->irq, atmel_nfc_interrupt,
			       IRQF_SHARED, "nfc", nc);
	if (ret) {
		dev_err(dev,
			"Could not get register NFC interrupt handler (err = %d)\n",
			ret);
		goto err;
	}

	/* Initial NFC configuration. */
	regmap_write(nc->base.smc, ATMEL_HSMC_NFC_CFG,
		     ATMEL_HSMC_NFC_CFG_DTO_MAX);

	ret = atmel_nand_controller_add_nands(&nc->base);
	if (ret)
		goto err;

	return 0;

err:
	atmel_hsmc_nand_controller_remove(&nc->base);

	return ret;
}

const struct atmel_nand_controller_ops atmel_hsmc_nc_ops = {
	.probe = atmel_hsmc_nand_controller_probe,
	.remove = atmel_hsmc_nand_controller_remove,
	.ecc_init = atmel_hsmc_nand_ecc_init,
	.nand_init = atmel_hsmc_nand_init,
};

static const struct atmel_nand_controller_caps atmel_sama5_nc_caps = {
	.has_dma = true,
	.ale_offs = BIT(21),
	.cle_offs = BIT(22),
	.ops = &atmel_hsmc_nc_ops,
};

/* Only used to parse old bindings. */
static const struct atmel_nand_controller_caps atmel_sama5_nand_caps = {
	.has_dma = true,
	.ale_offs = BIT(21),
	.cle_offs = BIT(22),
	.ops = &atmel_hsmc_nc_ops,
	.legacy_of_bindings = true,
};

static int atmel_smc_nand_controller_probe(struct platform_device *pdev,
				const struct atmel_nand_controller_caps *caps)
{
	struct device *dev = &pdev->dev;
	struct atmel_smc_nand_controller *nc;
	int ret;

	nc = devm_kzalloc(dev, sizeof(*nc), GFP_KERNEL);
	if (!nc)
		return -ENOMEM;

	ret = atmel_nand_controller_init(&nc->base, pdev, caps);
	if (ret)
		return ret;

	ret = atmel_smc_nand_controller_init(nc);
	if (ret)
		return ret;

	return atmel_nand_controller_add_nands(&nc->base);
}

static int
atmel_smc_nand_controller_remove(struct atmel_nand_controller *nc)
{
	int ret;

	ret = atmel_nand_controller_remove_nands(nc);
	if (ret)
		return ret;

	atmel_nand_controller_cleanup(nc);

	return 0;
}

const struct atmel_nand_controller_ops atmel_smc_nc_ops = {
	.probe = atmel_smc_nand_controller_probe,
	.remove = atmel_smc_nand_controller_remove,
	.ecc_init = atmel_nand_ecc_init,
	.nand_init = atmel_smc_nand_init,
};

static const struct atmel_nand_controller_caps atmel_rm9200_nc_caps = {
	.ale_offs = BIT(21),
	.cle_offs = BIT(22),
	.ops = &atmel_smc_nc_ops,
};

static const struct atmel_nand_controller_caps atmel_sam9261_nc_caps = {
	.ale_offs = BIT(22),
	.cle_offs = BIT(21),
	.ops = &atmel_smc_nc_ops,
};

static const struct atmel_nand_controller_caps atmel_sam9g45_nc_caps = {
	.has_dma = true,
	.ale_offs = BIT(21),
	.cle_offs = BIT(22),
	.ops = &atmel_smc_nc_ops,
};

/* Only used to parse old bindings. */
static const struct atmel_nand_controller_caps atmel_rm9200_nand_caps = {
	.ale_offs = BIT(21),
	.cle_offs = BIT(22),
	.ops = &atmel_smc_nc_ops,
	.legacy_of_bindings = true,
};

static const struct atmel_nand_controller_caps atmel_sam9261_nand_caps = {
	.ale_offs = BIT(22),
	.cle_offs = BIT(21),
	.ops = &atmel_smc_nc_ops,
	.legacy_of_bindings = true,
};

static const struct atmel_nand_controller_caps atmel_sam9g45_nand_caps = {
	.has_dma = true,
	.ale_offs = BIT(21),
	.cle_offs = BIT(22),
	.ops = &atmel_smc_nc_ops,
	.legacy_of_bindings = true,
};

static const struct of_device_id atmel_nand_controller_of_ids[] = {
	{
		.compatible = "atmel,at91rm9200-nand-controller",
		.data = &atmel_rm9200_nc_caps,
	},
	{
		.compatible = "atmel,at91sam9260-nand-controller",
		.data = &atmel_rm9200_nc_caps,
	},
	{
		.compatible = "atmel,at91sam9261-nand-controller",
		.data = &atmel_sam9261_nc_caps,
	},
	{
		.compatible = "atmel,at91sam9g45-nand-controller",
		.data = &atmel_sam9g45_nc_caps,
	},
	{
		.compatible = "atmel,sama5d3-nand-controller",
		.data = &atmel_sama5_nc_caps,
	},
	/* Support for old/deprecated bindings: */
	{
		.compatible = "atmel,at91rm9200-nand",
		.data = &atmel_rm9200_nand_caps,
	},
	{
		.compatible = "atmel,sama5d4-nand",
		.data = &atmel_rm9200_nand_caps,
	},
	{
		.compatible = "atmel,sama5d2-nand",
		.data = &atmel_rm9200_nand_caps,
	},
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, atmel_nand_controller_of_ids);

static int atmel_nand_controller_probe(struct platform_device *pdev)
{
	const struct atmel_nand_controller_caps *caps;

	if (pdev->id_entry)
		caps = (void *)pdev->id_entry->driver_data;
	else
		caps = of_device_get_match_data(&pdev->dev);

	if (!caps) {
		dev_err(&pdev->dev, "Could not retrieve NFC caps\n");
		return -EINVAL;
	}

	if (caps->legacy_of_bindings) {
		u32 ale_offs = 21;

		/*
		 * If we are parsing legacy DT props and the DT contains a
		 * valid NFC node, forward the request to the sama5 logic.
		 */
		if (of_find_compatible_node(pdev->dev.of_node, NULL,
					    "atmel,sama5d3-nfc"))
			caps = &atmel_sama5_nand_caps;

		/*
		 * Even if the compatible says we are dealing with an
		 * at91rm9200 controller, the atmel,nand-has-dma specify that
		 * this controller supports DMA, which means we are in fact
		 * dealing with an at91sam9g45+ controller.
		 */
		if (!caps->has_dma &&
		    of_property_read_bool(pdev->dev.of_node,
					  "atmel,nand-has-dma"))
			caps = &atmel_sam9g45_nand_caps;

		/*
		 * All SoCs except the at91sam9261 are assigning ALE to A21 and
		 * CLE to A22. If atmel,nand-addr-offset != 21 this means we're
		 * actually dealing with an at91sam9261 controller.
		 */
		of_property_read_u32(pdev->dev.of_node,
				     "atmel,nand-addr-offset", &ale_offs);
		if (ale_offs != 21)
			caps = &atmel_sam9261_nand_caps;
	}

	return caps->ops->probe(pdev, caps);
}

static int atmel_nand_controller_remove(struct platform_device *pdev)
{
	struct atmel_nand_controller *nc = platform_get_drvdata(pdev);

	return nc->caps->ops->remove(nc);
}

static struct platform_driver atmel_nand_controller_driver = {
	.driver = {
		.name = "atmel-nand-controller",
		.of_match_table = of_match_ptr(atmel_nand_controller_of_ids),
	},
	.probe = atmel_nand_controller_probe,
	.remove = atmel_nand_controller_remove,
};
module_platform_driver(atmel_nand_controller_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Boris Brezillon <boris.brezillon@free-electrons.com>");
MODULE_DESCRIPTION("NAND Flash Controller driver for Atmel SoCs");
MODULE_ALIAS("platform:atmel-nand-controller");
