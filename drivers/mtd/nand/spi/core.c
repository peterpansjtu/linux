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
#include <linux/of.h>

static int spinand_erase_skip_bbt(struct mtd_info *mtd,
				  struct erase_info *einfo);

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
 * spinand_get_cfg - get configuration register value
 * @chip: SPI NAND device structure
 * @cfg: buffer to store value
 * Description:
 *   Configuration register includes OTP config, Lock Tight enable/disable
 *   and Internal ECC enable/disable.
 */
static int spinand_get_cfg(struct spinand_device *chip, u8 *cfg)
{
	return spinand_read_reg(chip, REG_CFG, cfg);
}

/*
 * spinand_set_cfg - set value to configuration register
 * @chip: SPI NAND device structure
 * @cfg: value to set
 * Description:
 *   Configuration register includes OTP config, Lock Tight enable/disable
 *   and Internal ECC enable/disable.
 */
static int spinand_set_cfg(struct spinand_device *chip, u8 cfg)
{
	return spinand_write_reg(chip, REG_CFG, cfg);
}

/*
 * spinand_enable_ecc - enable internal ECC
 * @chip: SPI NAND device structure
 */
static void spinand_enable_ecc(struct spinand_device *chip)
{
	u8 cfg = 0;

	spinand_get_cfg(chip, &cfg);
	if ((cfg & CFG_ECC_MASK) == CFG_ECC_ENABLE)
		return;
	cfg |= CFG_ECC_ENABLE;
	spinand_set_cfg(chip, cfg);
}

/*
 * spinand_disable_ecc - disable internal ECC
 * @chip: SPI NAND device structure
 */
static void spinand_disable_ecc(struct spinand_device *chip)
{
	u8 cfg = 0;

	spinand_get_cfg(chip, &cfg);
	if ((cfg & CFG_ECC_MASK) == CFG_ECC_ENABLE) {
		cfg &= ~CFG_ECC_ENABLE;
		spinand_set_cfg(chip, cfg);
	}
}

/*
 * spinand_write_enable - send command 06h to enable write or erase the
 * NAND cells
 * @chip: SPI NAND device structure
 */
static int spinand_write_enable(struct spinand_device *chip)
{
	struct spinand_op op;

	spinand_init_op(&op);
	op.cmd = SPINAND_CMD_WR_ENABLE;

	return spinand_exec_op(chip, &op);
}

/*
 * spinand_read_page_to_cache - send command 13h to read data from NAND array
 * to cache
 * @chip: SPI NAND device structure
 * @page_addr: page to read
 */
static int spinand_read_page_to_cache(struct spinand_device *chip,
				      u32 page_addr)
{
	struct spinand_op op;

	spinand_init_op(&op);
	op.cmd = SPINAND_CMD_PAGE_READ;
	op.n_addr = 3;
	op.addr[0] = (u8)(page_addr >> 16);
	op.addr[1] = (u8)(page_addr >> 8);
	op.addr[2] = (u8)page_addr;

	return spinand_exec_op(chip, &op);
}

/*
 * spinand_get_address_bits - return address should be transferred
 * by how many bits
 * @opcode: command's operation code
 */
static int spinand_get_address_bits(u8 opcode)
{
	switch (opcode) {
	case SPINAND_CMD_READ_FROM_CACHE_QUAD_IO:
		return 4;
	case SPINAND_CMD_READ_FROM_CACHE_DUAL_IO:
		return 2;
	default:
		return 1;
	}
}

/*
 * spinand_get_data_bits - return data should be transferred by how many bits
 * @opcode: command's operation code
 */
static int spinand_get_data_bits(u8 opcode)
{
	switch (opcode) {
	case SPINAND_CMD_READ_FROM_CACHE_QUAD_IO:
	case SPINAND_CMD_READ_FROM_CACHE_X4:
	case SPINAND_CMD_PROG_LOAD_X4:
	case SPINAND_CMD_PROG_LOAD_RDM_DATA_X4:
		return 4;
	case SPINAND_CMD_READ_FROM_CACHE_DUAL_IO:
	case SPINAND_CMD_READ_FROM_CACHE_X2:
		return 2;
	default:
		return 1;
	}
}

/*
 * spinand_read_from_cache - read data out from cache register
 * @chip: SPI NAND device structure
 * @page_addr: page to read
 * @column: the location to read from the cache
 * @len: number of bytes to read
 * @rbuf: buffer held @len bytes
 */
static int spinand_read_from_cache(struct spinand_device *chip, u32 page_addr,
				   u32 column, size_t len, u8 *rbuf)
{
	struct spinand_op op;

	spinand_init_op(&op);
	op.cmd = chip->read_cache_op;
	op.n_addr = 2;
	op.addr[0] = (u8)(column >> 8);
	op.addr[1] = (u8)column;
	op.addr_nbits = spinand_get_address_bits(chip->read_cache_op);
	op.n_rx = len;
	op.rx_buf = rbuf;
	op.data_nbits = spinand_get_data_bits(chip->read_cache_op);
	if (chip->manufacturer.manu->ops->prepare_op)
		chip->manufacturer.manu->ops->prepare_op(chip, &op,
							 page_addr, column);

	return spinand_exec_op(chip, &op);
}

/*
 * spinand_write_to_cache - write data to cache register
 * @chip: SPI NAND device structure
 * @page_addr: page to write
 * @column: the location to write to the cache
 * @len: number of bytes to write
 * @wrbuf: buffer held @len bytes
 */
static int spinand_write_to_cache(struct spinand_device *chip, u32 page_addr,
				  u32 column, size_t len, const u8 *wbuf)
{
	struct spinand_op op;

	spinand_init_op(&op);
	op.cmd = chip->write_cache_op;
	op.n_addr = 2;
	op.addr[0] = (u8)(column >> 8);
	op.addr[1] = (u8)column;
	op.addr_nbits = spinand_get_address_bits(chip->write_cache_op);
	op.n_tx = len;
	op.tx_buf = wbuf;
	op.data_nbits = spinand_get_data_bits(chip->write_cache_op);
	if (chip->manufacturer.manu->ops->prepare_op)
		chip->manufacturer.manu->ops->prepare_op(chip, &op,
							 page_addr, column);

	return spinand_exec_op(chip, &op);
}

/*
 * spinand_program_execute - send command 10h to write a page from
 * cache to the NAND array
 * @chip: SPI NAND device structure
 * @page_addr: the physical page location to write the page.
 */
static int spinand_program_execute(struct spinand_device *chip, u32 page_addr)
{
	struct spinand_op op;

	spinand_init_op(&op);
	op.cmd = SPINAND_CMD_PROG_EXC;
	op.n_addr = 3;
	op.addr[0] = (u8)(page_addr >> 16);
	op.addr[1] = (u8)(page_addr >> 8);
	op.addr[2] = (u8)page_addr;

	return spinand_exec_op(chip, &op);
}

/*
 * spinand_erase_block_erase - send command D8h to erase a block
 * @chip: SPI NAND device structure
 * @page_addr: the start page address of block to be erased.
 */
static int spinand_erase_block(struct spinand_device *chip, u32 page_addr)
{
	struct spinand_op op;

	spinand_init_op(&op);
	op.cmd = SPINAND_CMD_BLK_ERASE;
	op.n_addr = 3;
	op.addr[0] = (u8)(page_addr >> 16);
	op.addr[1] = (u8)(page_addr >> 8);
	op.addr[2] = (u8)page_addr;

	return spinand_exec_op(chip, &op);
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
 * spinand_get_ecc_status - get ecc correction information from status register
 * @chip: SPI NAND device structure
 * @status: status register value
 * @corrected: corrected bit flip number
 * @ecc_error: ecc correction error or not
 */
static void spinand_get_ecc_status(struct spinand_device *chip,
				   unsigned int status,
				   unsigned int *corrected,
				   unsigned int *ecc_error)
{
	return chip->ecc.engine->ops->get_ecc_status(chip, status, corrected,
						     ecc_error);
}

/*
 * spinand_do_read_page - read page from device to buffer
 * @mtd: MTD device structure
 * @page_addr: page address/raw address
 * @ecc_off: without ecc or not
 * @corrected: how many bit flip corrected
 * @oob_only: read OOB only or the whole page
 */
static int spinand_do_read_page(struct mtd_info *mtd, u32 page_addr,
				bool ecc_off, int *corrected, bool oob_only)
{
	struct spinand_device *chip = mtd_to_spinand(mtd);
	struct nand_device *nand = mtd_to_nand(mtd);
	int ret, ecc_error = 0;
	u8 status;

	spinand_read_page_to_cache(chip, page_addr);
	ret = spinand_wait(chip, &status);
	if (ret < 0) {
		dev_err(chip->dev, "error %d waiting page 0x%x to cache\n",
			ret, page_addr);
		return ret;
	}
	if (!oob_only)
		spinand_read_from_cache(chip, page_addr, 0,
					nand_page_size(nand) +
					nand_per_page_oobsize(nand),
					chip->buf);
	else
		spinand_read_from_cache(chip, page_addr, nand_page_size(nand),
					nand_per_page_oobsize(nand),
					chip->oobbuf);
	if (!ecc_off) {
		spinand_get_ecc_status(chip, status, corrected, &ecc_error);
		/*
		 * If there's an ECC error, print a message and notify MTD
		 * about it. Then complete the read, to load actual data on
		 * the buffer (instead of the status result).
		 */
		if (ecc_error) {
			dev_err(chip->dev,
				"internal ECC error reading page 0x%x\n",
				page_addr);
			mtd->ecc_stats.failed++;
		} else if (*corrected) {
			mtd->ecc_stats.corrected += *corrected;
		}
	}

	return 0;
}

/*
 * spinand_do_write_page - write data from buffer to device
 * @mtd: MTD device structure
 * @page_addr: page address/raw address
 * @oob_only: write OOB only or the whole page
 */
static int spinand_do_write_page(struct mtd_info *mtd, u32 page_addr,
				 bool oob_only)
{
	struct spinand_device *chip = mtd_to_spinand(mtd);
	struct nand_device *nand = mtd_to_nand(mtd);
	u8 status;
	int ret = 0;

	spinand_write_enable(chip);
	if (!oob_only)
		spinand_write_to_cache(chip, page_addr, 0,
				       nand_page_size(nand) +
				       nand_per_page_oobsize(nand), chip->buf);
	else
		spinand_write_to_cache(chip, page_addr, nand_page_size(nand),
				       nand_per_page_oobsize(nand),
				       chip->oobbuf);
	spinand_program_execute(chip, page_addr);
	ret = spinand_wait(chip, &status);
	if (ret < 0) {
		dev_err(chip->dev, "error %d reading page 0x%x from cache\n",
			ret, page_addr);
		return ret;
	}
	if ((status & STATUS_P_FAIL_MASK) == STATUS_P_FAIL) {
		dev_err(chip->dev, "program page 0x%x failed\n", page_addr);
		ret = -EIO;
	}
	return ret;
}

/*
 * spinand_transfer_oob - transfer oob to client buffer
 * @chip: SPI NAND device structure
 * @oob: oob destination address
 * @ops: oob ops structure
 * @len: size of oob to transfer
 */
static int spinand_transfer_oob(struct spinand_device *chip, u8 *oob,
				struct mtd_oob_ops *ops, size_t len)
{
	struct mtd_info *mtd = spinand_to_mtd(chip);
	int ret = 0;

	switch (ops->mode) {
	case MTD_OPS_PLACE_OOB:
	case MTD_OPS_RAW:
		memcpy(oob, chip->oobbuf + ops->ooboffs, len);
		break;
	case MTD_OPS_AUTO_OOB:
		ret = mtd_ooblayout_get_databytes(mtd, oob, chip->oobbuf,
						  ops->ooboffs, len);
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}

/*
 * spinand_fill_oob - transfer client buffer to oob
 * @chip: SPI NAND device structure
 * @oob: oob data buffer
 * @len: oob data write length
 * @ops: oob ops structure
 */
static int spinand_fill_oob(struct spinand_device *chip, uint8_t *oob,
			    size_t len, struct mtd_oob_ops *ops)
{
	struct mtd_info *mtd = spinand_to_mtd(chip);
	struct nand_device *nand = mtd_to_nand(mtd);
	int ret = 0;

	memset(chip->oobbuf, 0xff, nand_per_page_oobsize(nand));
	switch (ops->mode) {
	case MTD_OPS_PLACE_OOB:
	case MTD_OPS_RAW:
		memcpy(chip->oobbuf + ops->ooboffs, oob, len);
		break;
	case MTD_OPS_AUTO_OOB:
		ret = mtd_ooblayout_set_databytes(mtd, oob, chip->oobbuf,
						  ops->ooboffs, len);
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}

/*
 * spinand_read_pages - read data from device to buffer
 * @mtd: MTD device structure
 * @from: offset to read from
 * @ops: oob operations description structure
 * @max_bitflips: maximum bitflip count
 */
static int spinand_read_pages(struct mtd_info *mtd, loff_t from,
			      struct mtd_oob_ops *ops,
			      unsigned int *max_bitflips)
{
	struct spinand_device *chip = mtd_to_spinand(mtd);
	struct nand_device *nand = mtd_to_nand(mtd);
	int size, ret;
	unsigned int corrected = 0;
	bool ecc_off = ops->mode == MTD_OPS_RAW;
	int ooblen = ops->mode == MTD_OPS_AUTO_OOB ?
		     mtd->oobavail : mtd->oobsize;
	bool oob_only = !ops->datbuf;
	struct nand_page_iter iter;

	ops->retlen = 0;
	ops->oobretlen = 0;
	*max_bitflips = 0;

	nand_for_each_page(nand, from, ops->len, ops->ooboffs, ops->ooblen,
			   ooblen, &iter) {
		ret = spinand_do_read_page(mtd, iter.page, ecc_off,
					   &corrected, oob_only);
		if (ret)
			break;
		*max_bitflips = max(*max_bitflips, corrected);
		if (ops->datbuf) {
			size = min_t(int, iter.dataleft,
				     nand_page_size(nand) - iter.pageoffs);
			memcpy(ops->datbuf + ops->retlen,
			       chip->buf + iter.pageoffs, size);
			ops->retlen += size;
		}
		if (ops->oobbuf) {
			size = min_t(int, iter.oobleft, ooblen);
			ret = spinand_transfer_oob(chip,
						   ops->oobbuf + ops->oobretlen,
						   ops, size);
			if (ret) {
				dev_err(chip->dev, "Transfer oob error %d\n", ret);
				return ret;
			}
			ops->oobretlen += size;
		}
	}

	return ret;
}

/*
 * spinand_do_read_ops - read data from device to buffer
 * @mtd: MTD device structure
 * @from: offset to read from
 * @ops: oob operations description structure
 */
static int spinand_do_read_ops(struct mtd_info *mtd, loff_t from,
			       struct mtd_oob_ops *ops)
{
	struct spinand_device *chip = mtd_to_spinand(mtd);
	struct nand_device *nand = mtd_to_nand(mtd);
	int ret;
	struct mtd_ecc_stats stats;
	unsigned int max_bitflips = 0;
	bool ecc_off = ops->mode == MTD_OPS_RAW;

	ret = nand_check_address(nand, from);
	if (ret) {
		dev_err(chip->dev, "%s: invalid read address\n", __func__);
		return ret;
	}
	ret = nand_check_oob_ops(nand, from, ops);
	if (ret) {
		dev_err(chip->dev,
			"%s: invalid oob operation input\n", __func__);
		return ret;
	}
	mutex_lock(&chip->lock);
	stats = mtd->ecc_stats;
	if (ecc_off)
		spinand_disable_ecc(chip);
	ret = spinand_read_pages(mtd, from, ops, &max_bitflips);
	if (ecc_off)
		spinand_enable_ecc(chip);
	if (ret)
		goto out;

	if (mtd->ecc_stats.failed - stats.failed) {
		ret = -EBADMSG;
		goto out;
	}
	ret = max_bitflips;

out:
	mutex_unlock(&chip->lock);
	return ret;
}

/*
 * spinand_write_pages - write data from buffer to device
 * @mtd: MTD device structure
 * @to: offset to write to
 * @ops: oob operations description structure
 */
static int spinand_write_pages(struct mtd_info *mtd, loff_t to,
			       struct mtd_oob_ops *ops)
{
	struct spinand_device *chip = mtd_to_spinand(mtd);
	struct nand_device *nand = mtd_to_nand(mtd);
	int ret = 0;
	int size = 0;
	int oob_size = 0;
	int ooblen = ops->mode == MTD_OPS_AUTO_OOB ?
		     mtd->oobavail : mtd->oobsize;
	bool oob_only = !ops->datbuf;
	struct nand_page_iter iter;

	ops->retlen = 0;
	ops->oobretlen = 0;

	nand_for_each_page(nand, to, ops->len, ops->ooboffs, ops->ooblen,
			   ooblen, &iter) {
		memset(chip->buf, 0xff,
		       nand_page_size(nand) + nand_per_page_oobsize(nand));
		if (ops->oobbuf) {
			oob_size = min_t(int, iter.oobleft, ooblen);
			ret = spinand_fill_oob(chip,
					       ops->oobbuf + ops->oobretlen,
					       oob_size, ops);
			if (ret) {
				dev_err(chip->dev, "Fill oob error %d\n", ret);
				return ret;
			}
		}
		if (ops->datbuf) {
			size = min_t(int, iter.dataleft,
				     nand_page_size(nand) - iter.pageoffs);
			memcpy(chip->buf + iter.pageoffs,
			       ops->datbuf + ops->retlen, size);
		}
		ret = spinand_do_write_page(mtd, iter.page, oob_only);
		if (ret) {
			dev_err(chip->dev, "error %d writing page 0x%x\n",
				ret, iter.page);
			return ret;
		}
		if (ops->datbuf)
			ops->retlen += size;
		if (ops->oobbuf)
			ops->oobretlen += oob_size;
	}

	return ret;
}

/*
 * spinand_do_write_ops - write data from buffer to device
 * @mtd: MTD device structure
 * @to: offset to write to
 * @ops: oob operations description structure
 */
static int spinand_do_write_ops(struct mtd_info *mtd, loff_t to,
				struct mtd_oob_ops *ops)
{
	struct spinand_device *chip = mtd_to_spinand(mtd);
	struct nand_device *nand = mtd_to_nand(mtd);
	int ret = 0;
	bool ecc_off = ops->mode == MTD_OPS_RAW;

	ret = nand_check_address(nand, to);
	if (ret) {
		dev_err(chip->dev, "%s: invalid write address\n", __func__);
		return ret;
	}
	ret = nand_check_oob_ops(nand, to, ops);
	if (ret) {
		dev_err(chip->dev,
			"%s: invalid oob operation input\n", __func__);
		return ret;
	}
	if (nand_oob_ops_across_page(mtd_to_nand(mtd), ops)) {
		dev_err(chip->dev,
			"%s: try to across page when writing with OOB\n",
			__func__);
		return -EINVAL;
	}

	mutex_lock(&chip->lock);
	if (ecc_off)
		spinand_disable_ecc(chip);
	ret = spinand_write_pages(mtd, to, ops);
	if (ecc_off)
		spinand_enable_ecc(chip);
	mutex_unlock(&chip->lock);

	return ret;
}

/*
 * spinand_read - [MTD Interface] read page data
 * @mtd: MTD device structure
 * @from: offset to read from
 * @len: number of bytes to read
 * @retlen: pointer to variable to store the number of read bytes
 * @buf: the databuffer to put data
 */
static int spinand_read(struct mtd_info *mtd, loff_t from, size_t len,
			size_t *retlen, u8 *buf)
{
	struct mtd_oob_ops ops;
	int ret;

	memset(&ops, 0, sizeof(ops));
	ops.len = len;
	ops.datbuf = buf;
	ops.mode = MTD_OPS_PLACE_OOB;
	ret = spinand_do_read_ops(mtd, from, &ops);
	*retlen = ops.retlen;

	return ret;
}

/*
 * spinand_write - [MTD Interface] write page data
 * @mtd: MTD device structure
 * @to: offset to write to
 * @len: number of bytes to write
 * @retlen: pointer to variable to store the number of written bytes
 * @buf: the data to write
 */
static int spinand_write(struct mtd_info *mtd, loff_t to, size_t len,
			 size_t *retlen, const u8 *buf)
{
	struct mtd_oob_ops ops;
	int ret;

	memset(&ops, 0, sizeof(ops));
	ops.len = len;
	ops.datbuf = (uint8_t *)buf;
	ops.mode = MTD_OPS_PLACE_OOB;
	ret =  spinand_do_write_ops(mtd, to, &ops);
	*retlen = ops.retlen;

	return ret;
}

/*
 * spinand_read_oob - [MTD Interface] read page data and/or out-of-band
 * @mtd: MTD device structure
 * @from: offset to read from
 * @ops: oob operation description structure
 */
static int spinand_read_oob(struct mtd_info *mtd, loff_t from,
			    struct mtd_oob_ops *ops)
{
	int ret = -ENOTSUPP;

	ops->retlen = 0;
	switch (ops->mode) {
	case MTD_OPS_PLACE_OOB:
	case MTD_OPS_AUTO_OOB:
	case MTD_OPS_RAW:
		ret = spinand_do_read_ops(mtd, from, ops);
		break;
	}

	return ret;
}

/*
 * spinand_write_oob - [MTD Interface] write page data and/or out-of-band
 * @mtd: MTD device structure
 * @to: offset to write to
 * @ops: oob operation description structure
 */
static int spinand_write_oob(struct mtd_info *mtd, loff_t to,
			     struct mtd_oob_ops *ops)
{
	int ret = -ENOTSUPP;

	ops->retlen = 0;
	switch (ops->mode) {
	case MTD_OPS_PLACE_OOB:
	case MTD_OPS_AUTO_OOB:
	case MTD_OPS_RAW:
		ret = spinand_do_write_ops(mtd, to, ops);
		break;
	}

	return ret;
}

/*
 * spinand_block_bad - check if block at offset is bad by bad block marker
 * @mtd: MTD device structure
 * @offs: offset from device start
 */
static int spinand_block_bad(struct mtd_info *mtd, loff_t offs)
{
	struct nand_device *nand = mtd_to_nand(mtd);
	struct mtd_oob_ops ops = {0};
	u32 block_addr;
	u8 bad[2] = {0, 0};
	u8 ret = 0;
	unsigned int max_bitflips;

	block_addr = nand_offs_to_eraseblock(nand, offs);
	ops.mode = MTD_OPS_PLACE_OOB;
	ops.ooblen = 2;
	ops.oobbuf = bad;
	spinand_read_pages(mtd, nand_eraseblock_to_offs(nand, block_addr),
			   &ops, &max_bitflips);
	if (bad[0] != 0xFF || bad[1] != 0xFF)
		ret =  1;

	return ret;
}

/*
 * spinand_block_checkbad - check if a block is marked bad
 * @mtd: MTD device structure
 * @offs: offset from device start
 * @allowbbt: 1, if allowe to access the bbt area
 * Description:
 *   Check, if the block is bad. Either by reading the bad block table or
 *   reading bad block marker.
 */
static int spinand_block_checkbad(struct mtd_info *mtd, loff_t offs,
				  int allowbbt)
{
	struct nand_device *nand = mtd_to_nand(mtd);
	int ret;

	if (nand_bbt_is_initialized(nand))
		ret = nand_isbad_bbt(nand, offs, allowbbt);
	else
		ret = spinand_block_bad(mtd, offs);

	return ret;
}

/*
 * spinand_block_isbad - [MTD Interface] check if block at offset is bad
 * @mtd: MTD device structure
 * @offs: offset from device start
 */
static int spinand_block_isbad(struct mtd_info *mtd, loff_t offs)
{
	struct spinand_device *chip = mtd_to_spinand(mtd);
	int ret;

	mutex_lock(&chip->lock);
	ret = spinand_block_checkbad(mtd, offs, 0);
	mutex_unlock(&chip->lock);

	return ret;
}

/*
 * spinand_block_markbad_lowlevel - mark a block bad
 * @mtd: MTD device structure
 * @offs: offset from device start
 *
 * This function performs the generic bad block marking steps (i.e., bad
 * block table(s) and/or marker(s)).
 *
 * We try operations in the following order:
 *  (1) erase the affected block, to allow OOB marker to be written cleanly
 *  (2) write bad block marker to OOB area of affected block (unless flag
 *      NAND_BBT_NO_OOB_BBM is present)
 *  (3) update the BBT
 */
static int spinand_block_markbad_lowlevel(struct mtd_info *mtd, loff_t offs)
{
	struct nand_device *nand = mtd_to_nand(mtd);
	struct mtd_oob_ops ops = {0};
	struct erase_info einfo = {0};
	u32 block_addr;
	u8 buf[2] = {0, 0};
	int res, ret = 0;

	if (!nand_bbt_is_initialized(nand) ||
	    !(nand->bbt.options & NAND_BBT_NO_OOB_BBM)) {
		/*erase bad block before mark bad block*/
		einfo.mtd = mtd;
		einfo.addr = offs;
		einfo.len = nand_eraseblock_size(nand);
		spinand_erase_skip_bbt(mtd, &einfo);

		block_addr = nand_offs_to_eraseblock(nand, offs);
		ops.mode = MTD_OPS_PLACE_OOB;
		ops.ooblen = 2;
		ops.oobbuf = buf;
		ret = spinand_do_write_ops(mtd,
					   nand_eraseblock_to_offs(nand,
								   block_addr),
					   &ops);
	}

	/* Mark block bad in BBT */
	if (nand_bbt_is_initialized(nand)) {
		res = nand_markbad_bbt(nand, offs);
		if (!ret)
			ret = res;
	}

	if (!ret)
		mtd->ecc_stats.badblocks++;

	return ret;
}

/*
 * spinand_block_markbad - [MTD Interface] mark block at the given offset
 * as bad
 * @mtd: MTD device structure
 * @offs: offset relative to mtd start
 */
static int spinand_block_markbad(struct mtd_info *mtd, loff_t offs)
{
	int ret;

	ret = spinand_block_isbad(mtd, offs);
	if (ret) {
		/* If it was bad already, return success and do nothing */
		if (ret > 0)
			return 0;
		return ret;
	}

	return spinand_block_markbad_lowlevel(mtd, offs);
}

/*
 * spinand_erase - erase block(s)
 * @mtd: MTD device structure
 * @einfo: erase instruction
 * @allowbbt: allow to access bbt
 */
static int spinand_erase(struct mtd_info *mtd, struct erase_info *einfo,
			 int allowbbt)
{
	struct spinand_device *chip = mtd_to_spinand(mtd);
	struct nand_device *nand = mtd_to_nand(mtd);
	loff_t offs = einfo->addr, len = einfo->len;
	u8 status;
	int ret;

	ret = nand_check_erase_ops(nand, einfo);
	if (ret) {
		dev_err(chip->dev, "invalid erase operation input\n");
		return ret;
	}

	mutex_lock(&chip->lock);
	einfo->fail_addr = MTD_FAIL_ADDR_UNKNOWN;
	einfo->state = MTD_ERASING;

	while (len) {
		/* Check if we have a bad block, we do not erase bad blocks! */
		if (spinand_block_checkbad(mtd, offs, allowbbt)) {
			dev_warn(chip->dev,
				"attempt to erase a bad block at 0x%012llx\n",
				 offs);
			einfo->state = MTD_ERASE_FAILED;
			goto erase_exit;
		}
		spinand_write_enable(chip);
		spinand_erase_block(chip, nand_offs_to_page(nand, offs));
		ret = spinand_wait(chip, &status);
		if (ret < 0) {
			dev_err(chip->dev, "block erase command wait failed\n");
			einfo->state = MTD_ERASE_FAILED;
			goto erase_exit;
		}
		if ((status & STATUS_E_FAIL_MASK) == STATUS_E_FAIL) {
			dev_err(chip->dev, "erase block 0x%012llx failed\n", offs);
			einfo->state = MTD_ERASE_FAILED;
			einfo->fail_addr = offs;
			goto erase_exit;
		}

		/* Increment page address and decrement length */
		len -= nand_eraseblock_size(nand);
		offs += nand_eraseblock_size(nand);
	}

	einfo->state = MTD_ERASE_DONE;

erase_exit:

	ret = einfo->state == MTD_ERASE_DONE ? 0 : -EIO;

	mutex_unlock(&chip->lock);

	/* Do call back function */
	if (!ret)
		mtd_erase_callback(einfo);

	return ret;
}

/*
 * spinand_erase_skip_bbt - [MTD Interface] erase block(s) except BBT
 * @mtd: MTD device structure
 * @einfo: erase instruction
 */
static int spinand_erase_skip_bbt(struct mtd_info *mtd,
				  struct erase_info *einfo)
{
	return spinand_erase(mtd, einfo, 0);
}

/*
 * spinand_block_isreserved - [MTD Interface] check if a block is
 * marked reserved.
 * @mtd: MTD device structure
 * @offs: offset from device start
 */
static int spinand_block_isreserved(struct mtd_info *mtd, loff_t offs)
{
	struct nand_device *nand = mtd_to_nand(mtd);

	if (!nand_bbt_is_initialized(nand))
		return 0;
	/* Return info from the table */
	return nand_isreserved_bbt(nand, offs);
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

/*
 * spinand_erase_bbt - erase block(s) including BBT
 * @nand: nand device structure
 * @einfo: erase instruction
 */
static int spinand_erase_bbt(struct nand_device *nand,
			     struct erase_info *einfo)
{
	return spinand_erase(nand_to_mtd(nand), einfo, 1);
}

/*
 * spinand_erase_bbt - write bad block marker to certain block
 * @nand: nand device structure
 * @block: block to mark bad
 */
static int spinand_markbad(struct nand_device *nand, int block)
{
	struct mtd_oob_ops ops = {0};
	u8 buf[2] = {0, 0};

	ops.mode = MTD_OPS_PLACE_OOB;
	ops.ooboffs = 0;
	ops.ooblen = 2;
	ops.oobbuf = buf;

	return spinand_do_write_ops(nand_to_mtd(nand),
				    nand_eraseblock_to_offs(nand, block),
				    &ops);
}

static const struct nand_ops spinand_ops = {
	.erase = spinand_erase_bbt,
	.markbad = spinand_markbad,
};

/*
 * Define some generic bad/good block scan pattern which are used
 * while scanning a device for factory marked good/bad blocks.
 */
static u8 scan_ff_pattern[] = { 0xff, 0xff };

#define BADBLOCK_SCAN_MASK (~NAND_BBT_NO_OOB)

/*
 * spinand_create_badblock_pattern - creates a BBT descriptor structure
 * @chip: SPI NAND device structure
 *
 * This function allocates and initializes a nand_bbt_descr for BBM detection.
 * The new descriptor is stored in nand->bbt.bbp. Thus, nand->bbt.bbp should
 * be NULL when passed to this function.
 */
static int spinand_create_badblock_pattern(struct spinand_device *chip)
{
	struct nand_device *nand = &chip->base;
	struct nand_bbt_descr *bd;

	if (nand->bbt.bbp) {
		dev_err(chip->dev,
			"Bad block pattern already allocated; not replacing\n");
		return -EINVAL;
	}
	bd = devm_kzalloc(chip->dev, sizeof(*bd), GFP_KERNEL);
	if (!bd)
		return -ENOMEM;
	bd->options = nand->bbt.options & BADBLOCK_SCAN_MASK;
	bd->offs = 0;
	bd->len = 2;
	bd->pattern = scan_ff_pattern;
	bd->options |= NAND_BBT_DYNAMICSTRUCT;
	nand->bbt.bbp = bd;

	return 0;
}

/*
 * spinand_scan_bbt - scan BBT in SPI NAND device
 * @chip: SPI NAND device structure
 */
static int spinand_scan_bbt(struct spinand_device *chip)
{
	struct nand_device *nand = &chip->base;
	int ret;

	/*
	 * It's better to put BBT marker in-band, since some oob area
	 * is not ecc protected by internal(on-die) ECC
	 */
	if (nand->bbt.options & NAND_BBT_USE_FLASH)
		nand->bbt.options |= NAND_BBT_NO_OOB;
	nand->bbt.td = NULL;
	nand->bbt.md = NULL;

	ret = spinand_create_badblock_pattern(chip);
	if (ret)
		return ret;

	return nand_scan_bbt(nand);
}

static const struct spinand_manufacturer *spinand_manufacturers[] = {
	&micron_spinand_manufacture
};

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
 * TODO: move of_get_nand_on_flash_bbt() to generic NAND core
 */
static bool of_get_nand_on_flash_bbt(struct device_node *np)
{
	return of_property_read_bool(np, "nand-on-flash-bbt");
}

/*
 * spinand_dt_init - Initialize SPI NAND by device tree node
 * @chip: SPI NAND device structure
 *
 * TODO: put ecc_mode, ecc_strength, ecc_step, etc in here and move
 * it in generic NAND core.
 */
static void spinand_dt_init(struct spinand_device *chip)
{
	struct nand_device *nand = &chip->base;
	struct device_node *dn = nand_get_of_node(nand);

	if (!dn)
		return;

	if (of_get_nand_on_flash_bbt(dn))
		nand->bbt.options |= NAND_BBT_USE_FLASH;
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
		goto err1;
	}

	chip->oobbuf = chip->buf + nand_page_size(nand);

	spinand_manufacturer_init(chip);

	nand->ops = &spinand_ops;
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
	mtd->_erase = spinand_erase_skip_bbt;
	mtd->_read = spinand_read;
	mtd->_write = spinand_write;
	mtd->_read_oob = spinand_read_oob;
	mtd->_write_oob = spinand_write_oob;
	mtd->_block_isbad = spinand_block_isbad;
	mtd->_block_markbad = spinand_block_markbad;
	mtd->_block_isreserved = spinand_block_isreserved;

	if (!mtd->bitflip_threshold)
		mtd->bitflip_threshold = DIV_ROUND_UP(mtd->ecc_strength * 3,
						      4);
	/* After power up, all blocks are locked, so unlock it here. */
	spinand_lock_block(chip, BL_ALL_UNLOCKED);

	/* Build bad block table */
	ret = spinand_scan_bbt(chip);
	if (ret) {
		dev_err(chip->dev, "Scan Bad Block Table failed.\n");
		goto err2;
	}

	return nand_register(nand);

err2:
	devm_kfree(chip->dev, chip->buf);
err1:
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
	struct nand_bbt_descr *bd = nand->bbt.bbp;

	nand_unregister(nand);
	spinand_manufacturer_cleanup(chip);
	devm_kfree(chip->dev, chip->buf);
	kfree(nand->bbt.bbt);
	if (bd->options & NAND_BBT_DYNAMICSTRUCT)
		devm_kfree(chip->dev, bd);

	return 0;
}
EXPORT_SYMBOL_GPL(spinand_unregister);

MODULE_DESCRIPTION("SPI NAND framework");
MODULE_AUTHOR("Peter Pan<peterpandong@micron.com>");
MODULE_LICENSE("GPL v2");
