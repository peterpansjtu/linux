/*
 *  Copyright © 2016 - Boris Brezillon <boris.brezillon@free-electrons.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __LINUX_MTD_NAND_H
#define __LINUX_MTD_NAND_H

#include <linux/mtd/mtd.h>
#include <linux/mtd/bbm.h>
/**
 * struct nand_memory_organization - memory organization structure
 * @pagesize: page size
 * @oobsize: OOB area size
 * @eraseblocksize: erase block size
 * @planesize: plane size
 * @nplanes: number of planes embedded in a die
 * @diesize: die size
 * @ndies: number of dies embedded in the device
 */
struct nand_memory_organization {
	int pagesize;
	int oobsize;
	int eraseblocksize;
	size_t planesize;
	int nplanes;
	u64 diesize;
	int ndies;
};

/**
 * struct nand_bbt - bad block table structure
 * @options: bad block specific options
 * @td: bad block table descriptor for flash lookup.
 * @md: bad block table mirror descriptor
 * @bbp: bad block pattern
 * @bbt: in memory BBT
 */
struct nand_bbt {
	unsigned int options;
	/*
	 * Discourage new custom usages here; suggest usage of the
	 * relevant NAND_BBT_* options instead
	 */
	struct nand_bbt_descr *td;
	struct nand_bbt_descr *md;
	struct nand_bbt_descr *bbp;
	u8 *bbt;
};

struct nand_device;

/**
 * struct nand_ops - NAND operations
 * @erase: erase the blocks covered by the erase_info description
 */
struct nand_ops {
	int (*erase)(struct nand_device *nand, struct erase_info *einfo);
	int (*markbad)(struct nand_device *mtd, int block);
};

/**
 * struct nand_device - NAND device
 * @mtd: MTD instance attached to the NAND device
 * @memorg: memory layout
 * @bbt: bad block table info
 * @ops: NAND operations attached to the NAND device
 */
struct nand_device {
	struct mtd_info mtd;
	struct nand_memory_organization memorg;
	struct nand_bbt bbt;

	const struct nand_ops *ops;
};

/**
 * struct nand_page_iter - NAND page iterator
 * @page: the page
 * @pageoffs: the offset within a page
 * @dataleft: the left page data to read/write
 * @ooboffs: the offset within page oob
 * @oobleft: the left oob data to read/write
 * @oobbytes_per_page: maximun oob bytes to read/write per page
 */
struct nand_page_iter {
	int page;
	int pageoffs;
	size_t dataleft;
	int ooboffs;
	size_t oobleft;
	int oobbytes_per_page;
};

/**
 * mtd_to_nand - Get the NAND device attached to the MTD instance
 * @mtd: MTD instance
 *
 * Returns the NAND device attached to @mtd.
 */
static inline struct nand_device *mtd_to_nand(struct mtd_info *mtd)
{
	return container_of(mtd, struct nand_device, mtd);
}

/**
 * nand_to_mtd - Get the MTD device attached to a NAND device
 * @nand: NAND device
 *
 * Returns the MTD device attached to @nand.
 */
static inline struct mtd_info *nand_to_mtd(struct nand_device *nand)
{
	return &nand->mtd;
}

/**
 * nand_page_to_offs - Convert a page number to an absolute offset
 * @nand: NAND device
 * @page: page number
 *
 * Returns the offset pointing to the beginning of @page.
 */
static inline loff_t nand_page_to_offs(struct nand_device *nand, int page)
{
	return (loff_t)nand->memorg.pagesize * page;
}

/**
 * nand_offs_to_page - Convert an absolute offset to a page offset
 * @nand: NAND device
 * @offs: absolute offset
 *
 * Returns the page number containing @offs.
 */
static inline int nand_offs_to_page(struct nand_device *nand, loff_t offs)
{
	u64 page = offs;

	do_div(page, nand->memorg.pagesize);

	return page;
}

/**
 * nand_len_to_pages - Convert a length into a number of pages
 * @nand: NAND device
 * @len: length in bytes
 *
 * Returns the number of pages required to store @len bytes.
 * This functions assumes your storing those data at a page-aligned offset.
 */
static inline int nand_len_to_pages(struct nand_device *nand, size_t len)
{
	return DIV_ROUND_UP(len, nand->memorg.pagesize);
}

/**
 * nand_pages_to_len - Convert a number of pages into a length expressed in
 *		       bytes
 * @nand: NAND device
 * @npages: number of pages
 *
 * Returns the size taken by @npages pages.
 */
static inline size_t nand_pages_to_len(struct nand_device *nand, int npages)
{
	return (size_t)npages * nand->memorg.pagesize;
}

/**
 * nand_page_size - Get NAND page size
 * @nand: NAND device
 *
 * Returns the page size.
 */
static inline size_t nand_page_size(struct nand_device *nand)
{
	return nand->memorg.pagesize;
}

/**
 * nand_per_page_oobsize - Get NAND OOB size
 * @nand: NAND device
 *
 * Returns the OOB size.
 */
static inline int nand_per_page_oobsize(struct nand_device *nand)
{
	return nand->memorg.oobsize;
}

/**
 * nand_page_iter_init - Initialize a NAND page iterator
 * @nand: NAND device
 * @offs: absolute offset
 * @len: page data length to read/write
 * @ooboffs: oob offset within page
 * @ooblen: oob data length to read/write
 * @oobbytes_per_page: oob data can read/write per page
 * @iter: page iterator
 */
static inline void nand_page_iter_init(struct nand_device *nand,
				       loff_t offs, size_t len, u32 ooboffs,
				       size_t ooblen, u32 oobbytes_per_page,
				       struct nand_page_iter *iter)
{
	u64 page = offs;

	iter->pageoffs = do_div(page, nand->memorg.pagesize);
	iter->page = page;
	iter->dataleft = len;
	iter->ooboffs = ooboffs;
	iter->oobleft = ooblen;
	iter->oobbytes_per_page = oobbytes_per_page;
}

/**
 * nand_page_iter_next - Move to the next page
 * @nand: NAND device
 * @iter: page iterator
 */
static inline void nand_page_iter_next(struct nand_device *nand,
				       struct nand_page_iter *iter)
{
	iter->page++;
	iter->pageoffs = 0;
	if (iter->dataleft)
		iter->dataleft -= min_t (int,
					 nand_page_size(nand) - iter->pageoffs,
					 iter->dataleft);
	if (iter->oobleft)
		iter->oobleft -= min_t(int,
				       iter->oobbytes_per_page - iter->ooboffs,
				       iter->oobleft);
}

/**
 * nand_page_iter_end - Should end iteration or not
 * @nand: NAND device
 * @iter: page iterator
 */
static inline bool nand_page_iter_end(struct nand_device *nand,
				      struct nand_page_iter *iter)
{
	if (iter->dataleft || iter->oobleft)
		return false;
	return true;
}

/**
 * nand_for_each_page - Iterate nand pages
 * @nand: NAND device
 * @start: start address to read/write
 * @len: page data length to read/write
 * @ooboffs: oob offset within page
 * @ooblen: oob data length to read/write
 * @oobbytes_per_page: oob data can read/write per page
 * @iter: page iterator
 */
#define nand_for_each_page(nand, start, len, ooboffs, ooblen,	\
			   oobbytes_per_page, iter)	\
	for (nand_page_iter_init(nand, start, len, ooboffs, ooblen,	\
				 oobbytes_per_page, iter);	\
	     !nand_page_iter_end(nand, iter);		\
	     nand_page_iter_next(nand, iter))

/**
 * nand_per_page_oobsize - Get NAND erase block size
 * @nand: NAND device
 *
 * Returns the erase block size.
 */
static inline size_t nand_eraseblock_size(struct nand_device *nand)
{
	return nand->memorg.eraseblocksize;
}

/**
 * nand_page_to_offs - Convert an eraseblock number to an absolute offset
 * @nand: NAND device
 * @block: eraseblock number
 *
 * Returns the offset pointing to the beginning of @block.
 */
static inline loff_t nand_eraseblock_to_offs(struct nand_device *nand,
					     int block)
{
	return (loff_t)nand->memorg.eraseblocksize * block;
}

/**
 * nand_offs_to_eraseblock - Convert an absolute offset to an eraseblock offset
 * @nand: NAND device
 * @offs: absolute offset
 *
 * Returns the eraseblock number containing @offs.
 */
static inline int nand_offs_to_eraseblock(struct nand_device *nand, loff_t offs)
{
	u64 block = offs;

	do_div(block, nand->memorg.eraseblocksize);

	return block;
}

/**
 * nand_len_to_eraseblocks - Convert a length into a number of erablocks
 * @nand: NAND device
 * @len: length in bytes
 *
 * Returns the number of eraseblocks required to store @len bytes.
 * This functions assumes your storing those data at an eraseblock-aligned
 * offset.
 */
static inline int nand_len_to_eraseblocks(struct nand_device *nand, size_t len)
{
	return DIV_ROUND_UP(len, nand->memorg.eraseblocksize);
}

/**
 * nand_eraseblocks_to_len - Convert a number of eraseblocks into a length
 *			     expressed in bytes
 * @nand: NAND device
 * @nblocks: number of eraseblocks
 *
 * Returns the size taken by @nblock pages.
 */
static inline size_t nand_eraseblocks_to_len(struct nand_device *nand,
					     int nblocks)
{
	return (size_t)nblocks * nand->memorg.eraseblocksize;
}

/**
 * nand_per_eraseblock_oobsize - Get the amount of OOB bytes in an eraseblock
 * @nand: NAND device
 *
 * Returns the OOB size per eraseblock.
 */
static inline int nand_per_eraseblock_oobsize(struct nand_device *nand)
{
	int pagesperblock = nand->memorg.eraseblocksize /
			    nand->memorg.pagesize;

	return nand->memorg.oobsize * pagesperblock;
}

/**
 * nand_eraseblock_to_page - Convert an eraseblock number to a page number
 * @nand: NAND device
 * @block: eraseblock number
 *
 * Returns the page number assigned to the first page of @block eraseblock.
 */
static inline int nand_eraseblock_to_page(struct nand_device *nand, int block)
{
	int pagesperblock = nand->memorg.eraseblocksize /
			    nand->memorg.pagesize;

	return block * pagesperblock;
}

/**
 * nand_page_to_eraseblock - Convert a page number to an eraseblock number
 * @nand: NAND device
 * @page: page number
 *
 * Returns the eraseblock number containing @page.
 */
static inline int nand_page_to_eraseblock(struct nand_device *nand, int page)
{
	int pagesperblock = nand->memorg.eraseblocksize /
			    nand->memorg.pagesize;

	return page / pagesperblock;
}

/**
 * nand_eraseblocks_per_die - Get the number of eraseblocks per die
 * @nand: NAND device
 *
 * Returns the number of eraseblocks per die.
 */
static inline int nand_eraseblocks_per_die(struct nand_device *nand)
{
	u64 nblocks = nand->memorg.diesize;

	do_div(nblocks, nand->memorg.eraseblocksize);

	return nblocks;
}

/**
 * nand_eraseblocks_per_die - Get the number of eraseblocks per die
 * @nand: NAND device
 *
 * Returns the number of eraseblocks per die.
 */
static inline u64 nand_diesize(struct nand_device *nand)
{
	return nand->memorg.diesize;
}

/**
 * nand_ndies - Get the total of dies
 * @nand: NAND device
 *
 * Returns the number of dies exposed by @nand.
 */
static inline int nand_ndies(struct nand_device *nand)
{
	return nand->memorg.ndies;
}

/**
 * nand_die_to_offs - Convert a die number to an absolute offset
 * @nand: NAND device
 * @die: die number
 *
 * Returns the offset pointing to the beginning of @die.
 */
static inline loff_t nand_die_to_offs(struct nand_device *nand, int die)
{
	return (loff_t)nand->memorg.diesize * die;
}

/**
 * nand_offs_to_die - Convert an absolute offset to a die number
 * @nand: NAND device
 * @offs: absolute offset
 *
 * Returns the die number containing @offs.
 */
static inline int nand_offs_to_die(struct nand_device *nand, loff_t offs)
{
	return div64_u64((u64)offs, nand->memorg.diesize);
}

/**
 * nand_ndies - Get the total number of erasablocks
 * @nand: NAND device
 *
 * Returns the number of eraseblocks exposed by @nand.
 */
static inline int nand_neraseblocks(struct nand_device *nand)
{
	u64 nblocks = nand->memorg.ndies * nand->memorg.diesize;

	do_div(nblocks, nand->memorg.eraseblocksize);

	return nblocks;
}

/**
 * nand_size - Get NAND size
 * @nand: NAND device
 *
 * Returns the total size exposed by @nand.
 */
static inline u64 nand_size(struct nand_device *nand)
{
	return nand->memorg.ndies * nand->memorg.diesize;
}

/**
 * nand_check_address - check NAND address is valid or not
 * @nand: NAND device
 * @addr: address to check
 *
 * Returns 0 for valid address and -EINVAL for invalid address.
 */
static inline int nand_check_address(struct nand_device *nand, loff_t addr)
{
	return addr < nand_size(nand) ? 0 : -EINVAL;
}

/**
 * nand_check_oob_ops - check mtd_oob_ops is valid or not
 * @nand: NAND device
 * @start: start address to check
 * @ops: oob operation description struct
 *
 * Returns 0 for valid ops and -EINVAL for invalid ops.
 */
static inline int nand_check_oob_ops(struct nand_device *nand, loff_t start,
				     struct mtd_oob_ops *ops)
{
	struct mtd_info *mtd = nand_to_mtd(nand);
	int oobbytes_per_page = ops->mode == MTD_OPS_AUTO_OOB ?
				mtd->oobavail : mtd->oobsize;
	int pages = nand_len_to_pages(nand, nand_size(nand));
	int max_pages = pages - nand_offs_to_page(nand, start);
	int max_ooblen = max_pages * oobbytes_per_page;

	if ((!!ops->datbuf != !!ops->len) ||
	    (!!ops->oobbuf != !!ops->ooblen))
		return -EINVAL;
	if (ops->ooboffs >= oobbytes_per_page)
		return -EINVAL;
	if (ops->ooboffs + ops->ooblen > max_ooblen)
		return -EINVAL;

	return 0;
}

/**
 * nand_oob_ops_across_page - check oob operation across page or not
 * @nand: NAND device
 * @ops: oob operation description struct
 *
 * Returns true if oob operation across page and false when not.
 */
static inline bool nand_oob_ops_across_page(struct nand_device *nand,
					    struct mtd_oob_ops *ops)
{
	struct mtd_info *mtd = nand_to_mtd(nand);
	int oobbytes_per_page = ops->mode == MTD_OPS_AUTO_OOB ?
				mtd->oobavail : mtd->oobsize;

	return (ops->ooboffs + ops->ooblen) > oobbytes_per_page;
}

/**
 * nand_check_erase_ops - check erase operation is valid or not
 * @nand: NAND device
 * @einfo: erase instruction
 *
 * Returns 0 for valid erase operation and -EINVAL for invalid.
 */
static inline int nand_check_erase_ops(struct nand_device *nand,
				       struct erase_info *einfo)
{
	/* check address align on block boundary */
	if (einfo->addr & (nand_eraseblock_size(nand) - 1))
		return -EINVAL;
	/* check lendth align on block boundary */
	if (einfo->len & (nand_eraseblock_size(nand) - 1))
		return -EINVAL;
	/* Do not allow erase past end of device */
	if ((einfo->addr + einfo->len) > nand_size(nand))
		return -EINVAL;

	return 0;
}

/**
 * nand_register - Register a NAND device
 * @nand: NAND device
 *
 * Register a NAND device.
 * This function is just a wrapper around mtd_device_register()
 * registering the MTD device attached to @nand.
 */
static inline int nand_register(struct nand_device *nand)
{
	return mtd_device_register(&nand->mtd, NULL, 0);
}

/**
 * nand_unregister - Unregister a NAND device
 * @nand: NAND device
 *
 * Unregister a NAND device.
 * This function is just a wrapper around mtd_device_unregister()
 * unregistering the MTD device attached to @nand.
 */
static inline void nand_unregister(struct nand_device *nand)
{
	mtd_device_unregister(&nand->mtd);
}

/**
 * nand_read - Read data from NAND
 * @nand: NAND device
 * @offs: offset you want to read data from
 * @ops: options describing what you want to read (in-band/out-of-band data)
 *	 and how (raw or normal mode)
 *
 * Read data from NAND.
 */
static inline int nand_read(struct nand_device *nand, loff_t offs,
			    struct mtd_oob_ops *ops)
{
	return mtd_read_oob(&nand->mtd, offs, ops);
}

/**
 * nand_write - Write data to NAND
 * @nand: NAND device
 * @offs: offset you want to write data to
 * @ops: options describing what you want to write (in-band/out-of-band data)
 *	 and how (raw or normal mode)
 *
 * Read data from NAND.
 */
static inline int nand_write(struct nand_device *nand, loff_t offs,
			     struct mtd_oob_ops *ops)
{
	return mtd_write_oob(&nand->mtd, offs, ops);
}

/**
 * nand_erase - Erase a NAND portion
 * @nand: NAND device
 * @einfo: erase information
 * @force: whether bad or protected blocks should be erased or not
 *
 * Erase the NAND portion described by @einfo. If @force is passed, bad and
 * reserved block checking is bypassed and the implementation is asked to
 * force the erasure.
 */
static inline int nand_erase(struct nand_device *nand,
			     struct erase_info *einfo,
			     bool force)
{
	if (!force)
		return mtd_erase(&nand->mtd, einfo);

	return nand->ops->erase(nand, einfo);
}

/**
 * nand_markbad - Write a bad block marker to a block
 * @nand: NAND device
 * @block: block to mark bad
 *
 * Mark a block bad. This function is not using the BBT.
 */
static inline int nand_markbad(struct nand_device *nand, int block)
{
	return nand->ops->markbad(nand, block);
}

/**
 * nand_set_of_node - Attach a DT node to a NAND device
 * @nand: NAND device
 * @np: DT node
 *
 * Attach a DT node to a NAND device.
 */
static inline void nand_set_of_node(struct nand_device *nand,
				    struct device_node *np)
{
	mtd_set_of_node(&nand->mtd, np);
}

/**
 * nand_get_of_node - Retrieve the DT node attached a NAND device
 * @nand: NAND device
 *
 * Returns the DT node attached to @nand.
 */
static inline struct device_node *nand_get_of_node(struct nand_device *nand)
{
	return mtd_get_of_node(&nand->mtd);
}

/* BBT related functions */
enum nand_bbt_block_status {
	NAND_BBT_BLOCK_GOOD,
	NAND_BBT_BLOCK_WORN,
	NAND_BBT_BLOCK_RESERVED,
	NAND_BBT_BLOCK_FACTORY_BAD,
};

int nand_scan_bbt(struct nand_device *this);
int nand_update_bbt(struct nand_device *this, loff_t offs);
int nand_isreserved_bbt(struct nand_device *this, loff_t offs);
int nand_isbad_bbt(struct nand_device *this, loff_t offs, int allowbbt);
int nand_markbad_bbt(struct nand_device *this, loff_t offs);

void nand_bbt_update_entry(struct nand_device *this, int eraseblock,
			   enum nand_bbt_block_status status);
static inline bool nand_bbt_is_initialized(struct nand_device *this)
{
	return !!this->bbt.bbt;
}

#endif /* __LINUX_MTD_NAND_H */
