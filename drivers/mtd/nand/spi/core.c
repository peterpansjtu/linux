/*
 *
 * Copyright (c) 2009-2017 Micron Technology, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/mtd/spinand.h>
#include <linux/slab.h>

/*
 * spinand_exec_op - execute SPI NAND operation by controller ->exec_op() hook
 * @chip: SPI NAND device structure
 * @op: pointer to spinand_op struct
 */
static inline int spinand_exec_op(struct spinand_device *chip,
				  struct spinand_op *op)
{
	return chip->controller.controller->ops->exec_op(chip, op);
}

/*
 * spinand_init_op - initialize spinand_op struct
 * @op: pointer to spinand_op struct
 */
static inline void spinand_init_op(struct spinand_op *op)
{
	memset(op, 0, sizeof(struct spinand_op));
	op->addr_nbits = 1;
	op->data_nbits = 1;
}

/*
 * spinand_read_reg - read SPI NAND register
 * @chip: SPI NAND device structure
 * @reg; register to read
 * @buf: buffer to store value
 */
static int spinand_read_reg(struct spinand_device *chip, u8 reg, u8 *buf)
{
	struct spinand_op op;
	int ret;

	spinand_init_op(&op);
	op.cmd = SPINAND_CMD_GET_FEATURE;
	op.n_addr = 1;
	op.addr[0] = reg;
	op.n_rx = 1;
	op.rx_buf = buf;

	ret = spinand_exec_op(chip, &op);
	if (ret < 0)
		dev_err(chip->dev, "err: %d read register %d\n", ret, reg);

	return ret;
}

/*
 * spinand_write_reg - write SPI NAND register
 * @chip: SPI NAND device structure
 * @reg; register to write
 * @value: value to write
 */
static int spinand_write_reg(struct spinand_device *chip, u8 reg, u8 value)
{
	struct spinand_op op;
	int ret;

	spinand_init_op(&op);
	op.cmd = SPINAND_CMD_SET_FEATURE;
	op.n_addr = 1;
	op.addr[0] = reg;
	op.n_tx = 1;
	op.tx_buf = &value;

	ret = spinand_exec_op(chip, &op);
	if (ret < 0)
		dev_err(chip->dev, "err: %d write register %d\n", ret, reg);

	return ret;
}

/*
 * spinand_read_status - get status register value
 * @chip: SPI NAND device structure
 * @status: buffer to store value
 * Description:
 *   After read, write, or erase, the NAND device is expected to set the
 *   busy status.
 *   This function is to allow reading the status of the command: read,
 *   write, and erase.
 */
static int spinand_read_status(struct spinand_device *chip, u8 *status)
{
	return spinand_read_reg(chip, REG_STATUS, status);
}

/*
 * spinand_wait - wait until the command is done
 * @chip: SPI NAND device structure
 * @s: buffer to store status register value (can be NULL)
 */
static int spinand_wait(struct spinand_device *chip, u8 *s)
{
	unsigned long timeo =  jiffies + msecs_to_jiffies(400);
	u8 status;

	do {
		spinand_read_status(chip, &status);
		if ((status & STATUS_OIP_MASK) == STATUS_READY)
			goto out;
	} while (time_before(jiffies, timeo));

	/*
	 * Extra read, just in case the STATUS_READY bit has changed
	 * since our last check
	 */
	spinand_read_status(chip, &status);
out:
	if (s)
		*s = status;

	return (status & STATUS_OIP_MASK) == STATUS_READY ? 0 :	-ETIMEDOUT;
}

/*
 * spinand_read_id - read SPI NAND ID
 * @chip: SPI NAND device structure
 * @buf: buffer to store id
 * Description:
 *   Manufacturers' read ID method is not unique. Some need a dummy before
 *   reading, some's ID has three byte.
 *   This function send one byte opcode (9Fh) and then read
 *   SPINAND_MAX_ID_LEN (4 currently) bytes. Manufacturer's detect function
 *   need to filter out real ID from the 4 bytes.
 */
static int spinand_read_id(struct spinand_device *chip, u8 *buf)
{
	struct spinand_op op;

	spinand_init_op(&op);
	op.cmd = SPINAND_CMD_READ_ID;
	op.n_rx = SPINAND_MAX_ID_LEN;
	op.rx_buf = buf;

	return spinand_exec_op(chip, &op);
}

/*
 * spinand_reset - reset SPI NAND device
 * @chip: SPI NAND device structure
 */
static int spinand_reset(struct spinand_device *chip)
{
	struct spinand_op op;
	int ret;

	spinand_init_op(&op);
	op.cmd = SPINAND_CMD_RESET;

	ret = spinand_exec_op(chip, &op);
	if (ret < 0) {
		dev_err(chip->dev, "reset failed!\n");
		goto out;
	}
	ret = spinand_wait(chip, NULL);

out:
	return ret;
}

/*
 * spinand_lock_block - write block lock register to lock/unlock device
 * @chip: SPI NAND device structure
 * @lock: value to set to block lock register
 */
static int spinand_lock_block(struct spinand_device *chip, u8 lock)
{
	return spinand_write_reg(chip, REG_BLOCK_LOCK, lock);
}

/*
 * spinand_set_rd_wr_op - choose the best read write command
 * @chip: SPI NAND device structure
 * Description:
 *   Chose the fastest r/w command according to spi controller's and
 *   device's ability.
 */
static void spinand_set_rd_wr_op(struct spinand_device *chip)
{
	u32 controller_cap = chip->controller.controller->caps;
	u32 rw_mode = chip->rw_mode;

	if ((controller_cap & SPINAND_CAP_RD_QUAD) &&
	    (rw_mode & SPINAND_RD_QUAD))
		chip->read_cache_op = SPINAND_CMD_READ_FROM_CACHE_QUAD_IO;
	else if ((controller_cap & SPINAND_CAP_RD_X4) &&
		 (rw_mode & SPINAND_RD_X4))
		chip->read_cache_op = SPINAND_CMD_READ_FROM_CACHE_X4;
	else if ((controller_cap & SPINAND_CAP_RD_DUAL) &&
		 (rw_mode & SPINAND_RD_DUAL))
		chip->read_cache_op = SPINAND_CMD_READ_FROM_CACHE_DUAL_IO;
	else if ((controller_cap & SPINAND_CAP_RD_X2) &&
		 (rw_mode & SPINAND_RD_X2))
		chip->read_cache_op = SPINAND_CMD_READ_FROM_CACHE_X2;
	else
		chip->read_cache_op = SPINAND_CMD_READ_FROM_CACHE_FAST;

	if ((controller_cap & SPINAND_CAP_WR_X4) &&
	    (rw_mode & SPINAND_WR_X4))
		chip->write_cache_op = SPINAND_CMD_PROG_LOAD_X4;
	else
		chip->write_cache_op = SPINAND_CMD_PROG_LOAD;
}

static const struct spinand_manufacturer *spinand_manufacturers[] = {};

/*
 * spinand_manufacturer_detect - detect SPI NAND device by each manufacturer
 * @chip: SPI NAND device structure
 *
 * ->detect() should decode raw id in chip->id.data and initialize device
 * related part in spinand_device structure if it is the right device.
 * ->detect() can not be NULL.
 */
static int spinand_manufacturer_detect(struct spinand_device *chip)
{
	int i = 0;

	for (; i < ARRAY_SIZE(spinand_manufacturers); i++) {
		if (spinand_manufacturers[i]->ops->detect(chip)) {
			chip->manufacturer.manu = spinand_manufacturers[i];
			return 0;
		}
	}

	return -ENODEV;
}

/*
 * spinand_manufacturer_init - manufacturer initialization function.
 * @chip: SPI NAND device structure
 *
 * Manufacturer drivers should put all their specific initialization code in
 * their ->init() hook.
 */
static int spinand_manufacturer_init(struct spinand_device *chip)
{
	if (chip->manufacturer.manu->ops->init)
		return chip->manufacturer.manu->ops->init(chip);

	return 0;
}

/*
 * spinand_manufacturer_cleanup - manufacturer cleanup function.
 * @chip: SPI NAND device structure
 *
 * Manufacturer drivers should put all their specific cleanup code in their
 * ->cleanup() hook.
 */
static void spinand_manufacturer_cleanup(struct spinand_device *chip)
{
	/* Release manufacturer private data */
	if (chip->manufacturer.manu->ops->cleanup)
		return chip->manufacturer.manu->ops->cleanup(chip);
}

/*
 * spinand_dt_init - Initialize SPI NAND by device tree node
 * @chip: SPI NAND device structure
 *
 * TODO: put ecc_mode, ecc_strength, ecc_step, bbt, etc in here
 * and move it in generic NAND core.
 */
static void spinand_dt_init(struct spinand_device *chip)
{
}

/*
 * spinand_detect - detect the SPI NAND device
 * @chip: SPI NAND device structure
 */
static int spinand_detect(struct spinand_device *chip)
{
	struct nand_device *nand = &chip->base;
	int ret;

	spinand_reset(chip);
	spinand_read_id(chip, chip->id.data);
	chip->id.len = SPINAND_MAX_ID_LEN;

	ret = spinand_manufacturer_detect(chip);
	if (ret) {
		dev_err(chip->dev, "unknown raw ID %*phN\n",
			SPINAND_MAX_ID_LEN, chip->id.data);
		goto out;
	}

	dev_info(chip->dev, "%s (%s) is found.\n", chip->name,
		 chip->manufacturer.manu->name);
	dev_info(chip->dev,
		 "%d MiB, block size: %d KiB, page size: %d, OOB size: %d\n",
		 (int)(nand_size(nand) >> 20), nand_eraseblock_size(nand) >> 10,
		 nand_page_size(nand), nand_per_page_oobsize(nand));

out:
	return ret;
}

/*
 * spinand_init - initialize the SPI NAND device
 * @chip: SPI NAND device structure
 */
static int spinand_init(struct spinand_device *chip)
{
	struct mtd_info *mtd = spinand_to_mtd(chip);
	struct nand_device *nand = mtd_to_nand(mtd);
	struct spinand_ecc_engine *ecc_engine;
	int ret;

	spinand_dt_init(chip);
	spinand_set_rd_wr_op(chip);

	chip->buf = devm_kzalloc(chip->dev,
				 nand_page_size(nand) +
				 nand_per_page_oobsize(nand),
				 GFP_KERNEL);
	if (!chip->buf) {
		ret = -ENOMEM;
		goto err;
	}

	chip->oobbuf = chip->buf + nand_page_size(nand);

	spinand_manufacturer_init(chip);

	mtd->name = chip->name;
	mtd->size = nand_size(nand);
	mtd->erasesize = nand_eraseblock_size(nand);
	mtd->writesize = nand_page_size(nand);
	mtd->writebufsize = mtd->writesize;
	mtd->owner = THIS_MODULE;
	mtd->type = MTD_NANDFLASH;
	mtd->flags = MTD_CAP_NANDFLASH;
	if (!mtd->ecc_strength)
		mtd->ecc_strength = ecc_engine->strength ?
				    ecc_engine->strength : 1;

	mtd->oobsize = nand_per_page_oobsize(nand);
	ret = mtd_ooblayout_count_freebytes(mtd);
	if (ret < 0)
		ret = 0;
	mtd->oobavail = ret;

	if (!mtd->bitflip_threshold)
		mtd->bitflip_threshold = DIV_ROUND_UP(mtd->ecc_strength * 3,
						      4);
	/* After power up, all blocks are locked, so unlock it here. */
	spinand_lock_block(chip, BL_ALL_UNLOCKED);

	return nand_register(nand);

err:
	return ret;
}

/*
 * spinand_alloc - [SPI NAND Interface] allocate SPI NAND device instance
 * @dev: pointer to device model structure
 */
struct spinand_device *spinand_alloc(struct device *dev)
{
	struct spinand_device *chip;
	struct mtd_info *mtd;

	chip = devm_kzalloc(dev, sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return ERR_PTR(-ENOMEM);

	spinand_set_of_node(chip, dev->of_node);
	mutex_init(&chip->lock);
	chip->dev = dev;
	mtd = spinand_to_mtd(chip);
	mtd->dev.parent = dev;

	return chip;
}
EXPORT_SYMBOL_GPL(spinand_alloc);

/*
 * spinand_free - [SPI NAND Interface] free SPI NAND device instance
 * @chip: SPI NAND device structure
 */
void spinand_free(struct spinand_device *chip)
{
	devm_kfree(chip->dev, chip);
}
EXPORT_SYMBOL_GPL(spinand_free);

/*
 * spinand_register - [SPI NAND Interface] register SPI NAND device
 * @chip: SPI NAND device structure
 */
int spinand_register(struct spinand_device *chip)
{
	int ret;

	ret = spinand_detect(chip);
	if (ret) {
		dev_err(chip->dev,
			"Detect SPI NAND failed with error %d.\n", ret);
		return ret;
	}

	ret = spinand_init(chip);
	if (ret)
		dev_err(chip->dev,
			"Init SPI NAND failed with error %d.\n", ret);

	return ret;
}
EXPORT_SYMBOL_GPL(spinand_register);

/*
 * spinand_unregister - [SPI NAND Interface] unregister SPI NAND device
 * @chip: SPI NAND device structure
 */
int spinand_unregister(struct spinand_device *chip)
{
	struct nand_device *nand = &chip->base;

	nand_unregister(nand);
	spinand_manufacturer_cleanup(chip);
	devm_kfree(chip->dev, chip->buf);

	return 0;
}
EXPORT_SYMBOL_GPL(spinand_unregister);

MODULE_DESCRIPTION("SPI NAND framework");
MODULE_AUTHOR("Peter Pan<peterpandong@micron.com>");
MODULE_LICENSE("GPL v2");
