/*
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
#include <linux/module.h>
#include <linux/spi/spi.h>
#include <linux/mtd/spinand.h>

struct gen_spi_spinand_controller {
	struct spinand_controller ctrl;
	struct spi_device *spi;
};

#define to_gen_spi_spinand_controller(c) \
	container_of(c, struct gen_spi_spinand_controller, ctrl)

/*
 * gen_spi_spinand_exec_op - to process a command to send to the
 * SPI NAND by generic SPI bus
 * @chip: SPI NAND device structure
 * @op: SPI NAND operation descriptor
 */
static int gen_spi_spinand_exec_op(struct spinand_device *chip,
				   struct spinand_op *op)
{
	struct spi_message message;
	struct spi_transfer x[3];
	struct spinand_controller *scontroller = chip->controller.controller;
	struct gen_spi_spinand_controller *controller;

	controller = to_gen_spi_spinand_controller(scontroller);
	spi_message_init(&message);
	memset(x, 0, sizeof(x));
	x[0].len = 1;
	x[0].tx_nbits = 1;
	x[0].tx_buf = &op->cmd;
	spi_message_add_tail(&x[0], &message);

	if (op->n_addr + op->dummy_bytes) {
		x[1].len = op->n_addr + op->dummy_bytes;
		x[1].tx_nbits = op->addr_nbits;
		x[1].tx_buf = op->addr;
		spi_message_add_tail(&x[1], &message);
	}
	if (op->n_tx) {
		x[2].len = op->n_tx;
		x[2].tx_nbits = op->data_nbits;
		x[2].tx_buf = op->tx_buf;
		spi_message_add_tail(&x[2], &message);
	} else if (op->n_rx) {
		x[2].len = op->n_rx;
		x[2].rx_nbits = op->data_nbits;
		x[2].rx_buf = op->rx_buf;
		spi_message_add_tail(&x[2], &message);
	}
	return spi_sync(controller->spi, &message);
}

static struct spinand_controller_ops gen_spi_spinand_ops = {
	.exec_op = gen_spi_spinand_exec_op,
};

static int gen_spi_spinand_probe(struct spi_device *spi)
{
	struct spinand_device *chip;
	struct gen_spi_spinand_controller *controller;
	struct spinand_controller *spinand_controller;
	struct device *dev = &spi->dev;
	u16 mode = spi->mode;
	int ret;

	chip = spinand_alloc(dev);
	if (IS_ERR(chip)) {
		ret = PTR_ERR(chip);
		goto err1;
	}
	controller = devm_kzalloc(dev, sizeof(*controller), GFP_KERNEL);
	if (!controller) {
		ret = -ENOMEM;
		goto err2;
	}
	controller->spi = spi;
	spinand_controller = &controller->ctrl;
	spinand_controller->ops = &gen_spi_spinand_ops;
	spinand_controller->caps = SPINAND_CAP_RD_X1 | SPINAND_CAP_WR_X1;

	if ((mode & SPI_RX_QUAD) && (mode & SPI_TX_QUAD))
		spinand_controller->caps |= SPINAND_CAP_RD_QUAD;
	if ((mode & SPI_RX_DUAL) && (mode & SPI_TX_DUAL))
		spinand_controller->caps |= SPINAND_CAP_RD_DUAL;
	if (mode & SPI_RX_QUAD)
		spinand_controller->caps |= SPINAND_CAP_RD_X4;
	if (mode & SPI_RX_DUAL)
		spinand_controller->caps |= SPINAND_CAP_RD_X2;
	if (mode & SPI_TX_QUAD)
		spinand_controller->caps |= SPINAND_CAP_WR_QUAD |
					    SPINAND_CAP_WR_X4;
	if (mode & SPI_TX_DUAL)
		spinand_controller->caps |= SPINAND_CAP_WR_DUAL |
					    SPINAND_CAP_WR_X2;
	chip->controller.controller = spinand_controller;
	/*
	 * generic spi controller doesn't have ecc capability,
	 * so use on-die ecc.
	 */
	chip->ecc.type = SPINAND_ECC_ONDIE;
	spi_set_drvdata(spi, chip);

	ret = spinand_register(chip);
	if (ret)
		goto err3;

	return 0;

err3:
	devm_kfree(dev, controller);
err2:
	spinand_free(chip);
err1:
	return ret;
}

static int gen_spi_spinand_remove(struct spi_device *spi)
{
	struct spinand_device *chip = spi_get_drvdata(spi);
	struct spinand_controller *scontroller = chip->controller.controller;
	struct gen_spi_spinand_controller *controller;

	spinand_unregister(chip);
	controller = to_gen_spi_spinand_controller(scontroller);
	devm_kfree(&spi->dev, controller);
	spinand_free(chip);

	return 0;
}

static struct spi_driver gen_spi_spinand_driver = {
	.driver = {
		.name	= "generic_spinand",
		.owner	= THIS_MODULE,
	},
	.probe	= gen_spi_spinand_probe,
	.remove	= gen_spi_spinand_remove,
};
module_spi_driver(gen_spi_spinand_driver);

MODULE_DESCRIPTION("Generic SPI controller to support SPI NAND");
MODULE_AUTHOR("Peter Pan<peterpandong@micron.com>");
MODULE_LICENSE("GPL v2");
