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
#ifndef __LINUX_MTD_SPINAND_H
#define __LINUX_MTD_SPINAND_H

#include <linux/mutex.h>
#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/nand.h>

/*
 * Standard SPI NAND flash commands
 */
#define SPINAND_CMD_RESET			0xff
#define SPINAND_CMD_GET_FEATURE			0x0f
#define SPINAND_CMD_SET_FEATURE			0x1f
#define SPINAND_CMD_PAGE_READ			0x13
#define SPINAND_CMD_READ_FROM_CACHE		0x03
#define SPINAND_CMD_READ_FROM_CACHE_FAST	0x0b
#define SPINAND_CMD_READ_FROM_CACHE_X2		0x3b
#define SPINAND_CMD_READ_FROM_CACHE_DUAL_IO	0xbb
#define SPINAND_CMD_READ_FROM_CACHE_X4		0x6b
#define SPINAND_CMD_READ_FROM_CACHE_QUAD_IO	0xeb
#define SPINAND_CMD_BLK_ERASE			0xd8
#define SPINAND_CMD_PROG_EXC			0x10
#define SPINAND_CMD_PROG_LOAD			0x02
#define SPINAND_CMD_PROG_LOAD_RDM_DATA		0x84
#define SPINAND_CMD_PROG_LOAD_X4		0x32
#define SPINAND_CMD_PROG_LOAD_RDM_DATA_X4	0x34
#define SPINAND_CMD_READ_ID			0x9f
#define SPINAND_CMD_WR_DISABLE			0x04
#define SPINAND_CMD_WR_ENABLE			0x06

/* feature register */
#define REG_BLOCK_LOCK		0xa0
#define REG_CFG			0xb0
#define REG_STATUS		0xc0

/* status register */
#define STATUS_OIP_MASK		BIT(0)
#define STATUS_CRBSY_MASK	BIT(7)
#define STATUS_READY		0
#define STATUS_BUSY		BIT(0)

#define STATUS_E_FAIL_MASK	BIT(2)
#define STATUS_E_FAIL		BIT(2)

#define STATUS_P_FAIL_MASK	BIT(3)
#define STATUS_P_FAIL		BIT(3)

/* configuration register */
#define CFG_ECC_MASK		BIT(4)
#define CFG_ECC_ENABLE		BIT(4)

/* block lock register */
#define BL_ALL_UNLOCKED		0X00

struct spinand_op;
struct spinand_device;

#define SPINAND_MAX_ID_LEN	4

/*
 * struct spinand_id - SPI NAND id structure
 * @data: buffer containing the id bytes. Currently 4 bytes large, but can
 *	  be extended if required.
 * @len: ID length.
 */
struct spinand_id {
	u8 data[SPINAND_MAX_ID_LEN];
	int len;
};

struct spinand_controller_ops {
	int (*exec_op)(struct spinand_device *chip,
		       struct spinand_op *op);
};

struct spinand_manufacturer_ops {
	/*
	 * Firstly, ->detect() should not be NULL.
	 * ->detect() implementation for manufacturer A never sends
	 * any manufacturer specific SPI command to a SPI NAND from
	 * manufacturer B, so the proper way is to decode the raw id
	 * data in chip->id.data first, if manufacture ID dismatch,
	 * return directly and let others to detect.
	 */
	bool (*detect)(struct spinand_device *chip);
	int (*init)(struct spinand_device *chip);
	void (*cleanup)(struct spinand_device *chip);
	void (*prepare_op)(struct spinand_device *chip, struct spinand_op *op,
			   u32 page, u32 column);
};

struct spinand_manufacturer {
	u8 id;
	char *name;
	const struct spinand_manufacturer_ops *ops;
};

extern const struct spinand_manufacturer micron_spinand_manufacture;

struct spinand_ecc_engine_ops {
	void (*get_ecc_status)(struct spinand_device *chip,
			       unsigned int status, unsigned int *corrected,
			       unsigned int *ecc_errors);
	void (*disable_ecc)(struct spinand_device *chip);
	void (*enable_ecc)(struct spinand_device *chip);
};

enum spinand_ecc_type {
	SPINAND_ECC_ONDIE,
	SPINAND_ECC_HW,
};

struct spinand_ecc_engine {
	u32 strength;
	u32 steps;
	const struct spinand_ecc_engine_ops *ops;
};

#define SPINAND_CAP_RD_X1	BIT(0)
#define SPINAND_CAP_RD_X2	BIT(1)
#define SPINAND_CAP_RD_X4	BIT(2)
#define SPINAND_CAP_RD_DUAL	BIT(3)
#define SPINAND_CAP_RD_QUAD	BIT(4)
#define SPINAND_CAP_WR_X1	BIT(5)
#define SPINAND_CAP_WR_X2	BIT(6)
#define SPINAND_CAP_WR_X4	BIT(7)
#define SPINAND_CAP_WR_DUAL	BIT(8)
#define SPINAND_CAP_WR_QUAD	BIT(9)
#define SPINAND_CAP_HW_ECC	BIT(10)

struct spinand_controller {
	struct spinand_controller_ops *ops;
	u32 caps;
};

/*
 * struct spinand_device - SPI NAND device
 * @base: NAND device instance
 * @lock: protection lock
 * @name: name of the chip
 * @dev: struct device pointer
 * @id: ID structure
 * @read_cache_op: Opcode of read from cache
 * @write_cache_op: Opcode of program load
 * @buf: buffer for read/write data
 * @oobbuf: buffer for read/write oob
 * @rw_mode: read/write mode of SPI NAND chip
 * @controller: SPI NAND controller instance
 * @manufacturer: SPI NAND manufacturer instance, describe
 *                manufacturer related objects
 * @ecc_engine: SPI NAND ECC engine instance
 */
struct spinand_device {
	struct nand_device base;
	struct mutex lock;
	char *name;
	struct device *dev;
	struct spinand_id id;
	u8 read_cache_op;
	u8 write_cache_op;
	u8 *buf;
	u8 *oobbuf;
	u32 rw_mode;
	struct {
		struct spinand_controller *controller;
		void *priv;
	} controller;
	struct {
		const struct spinand_manufacturer *manu;
		void *priv;
	} manufacturer;
	struct {
		struct spinand_ecc_engine *engine;
		enum spinand_ecc_type type;
		void *context;
	} ecc;
};

static inline struct spinand_device *mtd_to_spinand(struct mtd_info *mtd)
{
	return container_of(mtd_to_nand(mtd), struct spinand_device, base);
}

static inline struct mtd_info *spinand_to_mtd(struct spinand_device *chip)
{
	return nand_to_mtd(&chip->base);
}

static inline void spinand_set_of_node(struct spinand_device *chip,
				       struct device_node *np)
{
	nand_set_of_node(&chip->base, np);
}

#define SPINAND_MAX_ADDR_LEN	4

/*
 * struct spinand_op - SPI NAND operation description
 * @cmd: opcode to send
 * @n_addr: address bytes
 * @addr_nbits: number of bit used to transfer address
 * @dummy_types: dummy bytes followed address
 * @addr: buffer held address
 * @n_tx: size of tx_buf
 * @tx_buf: data to be written
 * @n_rx: size of rx_buf
 * @rx_buf: data to be read
 * @data_nbits: number of bit used to transfer data
 */
struct spinand_op {
	u8 cmd;
	u8 n_addr;
	u8 addr_nbits;
	u8 dummy_bytes;
	u8 addr[SPINAND_MAX_ADDR_LEN];
	u32 n_tx;
	const u8 *tx_buf;
	u32 n_rx;
	u8 *rx_buf;
	u8 data_nbits;
};

/* SPI NAND supported OP mode */
#define SPINAND_RD_X1		0x00000001
#define SPINAND_RD_X2		0x00000002
#define SPINAND_RD_X4		0x00000004
#define SPINAND_RD_DUAL		0x00000008
#define SPINAND_RD_QUAD		0x00000010
#define SPINAND_WR_X1		0x00000020
#define SPINAND_WR_X2		0x00000040
#define SPINAND_WR_X4		0x00000080
#define SPINAND_WR_DUAL		0x00000100
#define SPINAND_WR_QUAD		0x00000200

#define SPINAND_RD_COMMON	(SPINAND_RD_X1 | SPINAND_RD_X2 | \
				 SPINAND_RD_X4 | SPINAND_RD_DUAL | \
				 SPINAND_RD_QUAD)
#define SPINAND_WR_COMMON	(SPINAND_WR_X1 | SPINAND_WR_X4)
#define SPINAND_OP_COMMON	(SPINAND_RD_COMMON | SPINAND_WR_COMMON)

struct spinand_device *spinand_alloc(struct device *dev);
void spinand_free(struct spinand_device *chip);
int spinand_register(struct spinand_device *chip);
int spinand_unregister(struct spinand_device *chip);
#endif /* __LINUX_MTD_SPINAND_H */
