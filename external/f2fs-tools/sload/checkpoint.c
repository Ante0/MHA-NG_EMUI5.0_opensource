/**
 * mount.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <f2fs_fs.h>
#include "sload.h"
#include "node.h"
#include "f2fs.h"
#include "segment.h"
#include "bit_operations.h"
#include <locale.h>

static int sanity_check_raw_super(struct f2fs_super_block *raw_super)
{
	unsigned int blocksize;

	if (F2FS_SUPER_MAGIC != le32_to_cpu(raw_super->magic)) {
		return -1;
	}

	if (F2FS_BLKSIZE != PAGE_CACHE_SIZE) {
		return -1;
	}

	blocksize = 1 << le32_to_cpu(raw_super->log_blocksize);
	if (F2FS_BLKSIZE != blocksize) {
		return -1;
	}

	if (le32_to_cpu(raw_super->log_sectorsize) > F2FS_MAX_LOG_SECTOR_SIZE ||
		le32_to_cpu(raw_super->log_sectorsize) <
						F2FS_MIN_LOG_SECTOR_SIZE) {
		return -1;
	}

	if (le32_to_cpu(raw_super->log_sectors_per_block) +
				le32_to_cpu(raw_super->log_sectorsize) !=
						F2FS_MAX_LOG_SECTOR_SIZE) {
		return -1;
	}

	return 0;
}

static int validate_super_block(struct f2fs_sb_info *sbi, int block)
{
	u64 offset;

	sbi->raw_super = malloc(sizeof(struct f2fs_super_block));
	ASSERT(sbi->raw_super);

	if (block == 0)
		offset = F2FS_SUPER_OFFSET;
	else
		offset = F2FS_BLKSIZE + F2FS_SUPER_OFFSET;

	if (dev_read(sbi->raw_super, offset, sizeof(struct f2fs_super_block))) {
		free(sbi->raw_super);
		return -1;
	}

	if (!sanity_check_raw_super(sbi->raw_super)) {
		/* get kernel version */
		if (config.kd >= 0) {
			dev_read_version(config.version, 0, VERSION_LEN);
			get_kernel_version(config.version);
		} else {
			memset(config.version, 0, VERSION_LEN);
		}

		/* build sb version */
		memcpy(config.sb_version, sbi->raw_super->version, VERSION_LEN);
		get_kernel_version(config.sb_version);
		memcpy(config.init_version, sbi->raw_super->init_version, VERSION_LEN);
		get_kernel_version(config.init_version);

		if (memcmp(config.sb_version, config.version, VERSION_LEN)) {
			int ret;

			memcpy(sbi->raw_super->version,
						config.version, VERSION_LEN);
			ret = dev_write(sbi->raw_super, offset,
					sizeof(struct f2fs_super_block));
			ASSERT(ret >= 0);

			config.auto_fix = 0;
			config.fix_on = 1;
		}
		return 0;
	}

	free(sbi->raw_super);
	MSG(0, "\tCan't find a valid F2FS superblock at 0x%x\n", block);

	return -EINVAL;
}

static int init_sb_info(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *raw_super = sbi->raw_super;
	u64 total_sectors;

	sbi->log_sectors_per_block =
		le32_to_cpu(raw_super->log_sectors_per_block);
	sbi->log_blocksize = le32_to_cpu(raw_super->log_blocksize);
	sbi->blocksize = 1 << sbi->log_blocksize;
	sbi->log_blocks_per_seg = le32_to_cpu(raw_super->log_blocks_per_seg);
	sbi->blocks_per_seg = 1 << sbi->log_blocks_per_seg;
	sbi->segs_per_sec = le32_to_cpu(raw_super->segs_per_sec);
	sbi->secs_per_zone = le32_to_cpu(raw_super->secs_per_zone);
	sbi->total_sections = le32_to_cpu(raw_super->section_count);
	sbi->total_node_count =
		(le32_to_cpu(raw_super->segment_count_nat) / 2)
		* sbi->blocks_per_seg * NAT_ENTRY_PER_BLOCK;
	sbi->root_ino_num = le32_to_cpu(raw_super->root_ino);
	sbi->node_ino_num = le32_to_cpu(raw_super->node_ino);
	sbi->meta_ino_num = le32_to_cpu(raw_super->meta_ino);
	sbi->cur_victim_sec = NULL_SEGNO;

	total_sectors = le64_to_cpu(raw_super->block_count) <<
					sbi->log_sectors_per_block;
	MSG(0, "Info: total FS sectors = %"PRIu64" (%"PRIu64" MB)\n",
				total_sectors, total_sectors >> 11);
	return 0;
}

static void *validate_checkpoint(struct f2fs_sb_info *sbi, block_t cp_addr,
				unsigned long long *version)
{
	void *cp_page_1, *cp_page_2;
	struct f2fs_checkpoint *cp_block;
	unsigned long blk_size = sbi->blocksize;
	unsigned long long cur_version = 0, pre_version = 0;
	unsigned int crc = 0;
	size_t crc_offset;

	/* Read the 1st cp block in this CP pack */
	cp_page_1 = malloc(PAGE_SIZE);
	ASSERT(cp_page_1);
	if (dev_read_block(cp_page_1, cp_addr) < 0)
		return NULL;

	cp_block = (struct f2fs_checkpoint *)cp_page_1;
	crc_offset = le32_to_cpu(cp_block->checksum_offset);
	if (crc_offset >= blk_size)
		goto invalid_cp1;

	crc = *(unsigned int *)((unsigned char *)cp_block + crc_offset);
	if (f2fs_crc_valid(crc, cp_block, crc_offset))
		goto invalid_cp1;

	pre_version = le64_to_cpu(cp_block->checkpoint_ver);

	/* Read the 2nd cp block in this CP pack */
	cp_page_2 = malloc(PAGE_SIZE);
	ASSERT(cp_page_2);
	cp_addr += le32_to_cpu(cp_block->cp_pack_total_block_count) - 1;

	if (dev_read_block(cp_page_2, cp_addr) < 0)
		goto invalid_cp2;

	cp_block = (struct f2fs_checkpoint *)cp_page_2;
	crc_offset = le32_to_cpu(cp_block->checksum_offset);
	if (crc_offset >= blk_size)
		goto invalid_cp2;

	crc = *(unsigned int *)((unsigned char *)cp_block + crc_offset);
	if (f2fs_crc_valid(crc, cp_block, crc_offset))
		goto invalid_cp2;

	cur_version = le64_to_cpu(cp_block->checkpoint_ver);

	if (cur_version == pre_version) {
		*version = cur_version;
		free(cp_page_2);
		return cp_page_1;
	}

invalid_cp2:
	free(cp_page_2);
invalid_cp1:
	free(cp_page_1);
	return NULL;
}

static int get_valid_checkpoint(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *raw_sb = sbi->raw_super;
	void *cp1, *cp2, *cur_page;
	unsigned long blk_size = sbi->blocksize;
	unsigned long long cp1_version = 0, cp2_version = 0, version;
	unsigned long long cp_start_blk_no;
	unsigned int cp_blks = 1 + le32_to_cpu(F2FS_RAW_SUPER(sbi)->cp_payload);
	int ret;

	sbi->ckpt = malloc(cp_blks * blk_size);
	if (!sbi->ckpt)
		return -ENOMEM;
	/*
	 * Finding out valid cp block involves read both
	 * sets( cp pack1 and cp pack 2)
	 */
	cp_start_blk_no = le32_to_cpu(raw_sb->cp_blkaddr);
	cp1 = validate_checkpoint(sbi, cp_start_blk_no, &cp1_version);

	/* The second checkpoint pack should start at the next segment */
	cp_start_blk_no += 1 << le32_to_cpu(raw_sb->log_blocks_per_seg);
	cp2 = validate_checkpoint(sbi, cp_start_blk_no, &cp2_version);

	if (cp1 && cp2) {
		if (ver_after(cp2_version, cp1_version)) {
			cur_page = cp2;
			sbi->cur_cp = 2;
			version = cp2_version;
		} else {
			cur_page = cp1;
			sbi->cur_cp = 1;
			version = cp1_version;
		}
	} else if (cp1) {
		cur_page = cp1;
		sbi->cur_cp = 1;
		version = cp1_version;
	} else if (cp2) {
		cur_page = cp2;
		sbi->cur_cp = 2;
		version = cp2_version;
	} else {
		free(cp1);
		free(cp2);
		goto fail_no_cp;
	}

	MSG(0, "Info: CKPT version = %llx\n", version);

	memcpy(sbi->ckpt, cur_page, blk_size);

	if (cp_blks > 1) {
		unsigned int i;
		unsigned long long cp_blk_no;

		cp_blk_no = le32_to_cpu(raw_sb->cp_blkaddr);
		if (cur_page == cp2)
			cp_blk_no += 1 <<
				le32_to_cpu(raw_sb->log_blocks_per_seg);
		/* copy sit bitmap */
		for (i = 1; i < cp_blks; i++) {
			unsigned char *ckpt = (unsigned char *)sbi->ckpt;
			ret = dev_read_block(cur_page, cp_blk_no + i);
			ASSERT(ret >= 0);
			memcpy(ckpt + i * blk_size, cur_page, blk_size);
		}
	}
	free(cp1);
	free(cp2);
	return 0;

fail_no_cp:
	free(sbi->ckpt);
	return -EINVAL;
}

static int sanity_check_ckpt(struct f2fs_sb_info *sbi)
{
	unsigned int total, fsmeta;
	struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);

	total = le32_to_cpu(raw_super->segment_count);
	fsmeta = le32_to_cpu(raw_super->segment_count_ckpt);
	fsmeta += le32_to_cpu(raw_super->segment_count_sit);
	fsmeta += le32_to_cpu(raw_super->segment_count_nat);
	fsmeta += le32_to_cpu(ckpt->rsvd_segment_count);
	fsmeta += le32_to_cpu(raw_super->segment_count_ssa);

	if (fsmeta >= total)
		return 1;

	return 0;
}

/* Because we have store Node Info into the 'Next' Area, so
   we should get_node_info from Next Area*/

int f2fs_do_mount(struct f2fs_sb_info *sbi)
{
	int ret;

	sbi->active_logs = NR_CURSEG_TYPE;
	ret = validate_super_block(sbi, 0);
	if (ret) {
		ret = validate_super_block(sbi, 1);
		if (ret)
			return -1;
	}

	init_sb_info(sbi);

	ret = get_valid_checkpoint(sbi);
	if (ret) {
		ERR_MSG("Can't find valid checkpoint\n");
		return -1;
	}

	if (sanity_check_ckpt(sbi)) {
		ERR_MSG("Checkpoint is polluted\n");
		return -1;
	}

	sbi->total_valid_node_count = le32_to_cpu(sbi->ckpt->valid_node_count);
	sbi->total_valid_inode_count =
			le32_to_cpu(sbi->ckpt->valid_inode_count);
	sbi->user_block_count = le64_to_cpu(sbi->ckpt->user_block_count);
	sbi->total_valid_block_count =
			le64_to_cpu(sbi->ckpt->valid_block_count);
	sbi->last_valid_block_count = sbi->total_valid_block_count;
	sbi->alloc_valid_block_count = 0;

	if (build_segment_manager(sbi)) {
		ERR_MSG("build_segment_manager failed\n");
		return -1;
	}

	if (build_node_manager(sbi)) {
		ERR_MSG("build_segment_manager failed\n");
		return -1;
	}

    /* Flush all the ssa staged journal to sit area*/
    remove_nats_in_journal(sbi);
    remove_sits_in_journal(sbi);

	return 0;
}

void f2fs_do_umount(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct f2fs_sm_info *sm_i = SM_I(sbi);
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	unsigned int i;

	/* free nm_info */
	free(nm_i->nat_bitmap);
	free(nm_i->nat_flip_bitmap);
	free(nm_i->nid_bitmap);
	free(sbi->nm_info);

	/* free sit_info */
	for (i = 0; i < TOTAL_SEGS(sbi); i++) {
		free(sit_i->sentries[i].cur_valid_map);
		free(sit_i->sentries[i].ckpt_valid_map);
	}
	free(sit_i->sit_bitmap);
	free(sm_i->sit_info);
	free(sm_i->flip_bitmap);

	/* free sm_info */
	for (i = 0; i < NR_CURSEG_TYPE; i++)
		free(sm_i->curseg_array[i].sum_blk);

	free(sm_i->curseg_array);
	free(sbi->sm_info);

	free(sbi->ckpt);
	free(sbi->raw_super);
}

static inline block_t __cp_payload(struct f2fs_sb_info *sbi)
{
    return le32_to_cpu(F2FS_RAW_SUPER(sbi)->cp_payload);
}

int f2fs_do_checkpoint(struct f2fs_sb_info *sbi)
{
    struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct curseg_info *curseg;
	int data_sum_blks;
	block_t start_blk;
	int ret, i;
	u32 crc32 = 0;
	int cp_payload_blks = __cp_payload(sbi);

	u64 ckpt_ver = le64_to_cpu(ckpt->checkpoint_ver);
	u64 user_block_count = le64_to_cpu(ckpt->user_block_count);
	u32 rsvd_segment_count = le32_to_cpu(ckpt->rsvd_segment_count);
	u32 overprov_segment_count = le32_to_cpu(ckpt->overprov_segment_count);

	flip_nat_bitmap(sbi);
	flush_sit_entries(sbi);

	memset(ckpt, 0, F2FS_BLKSIZE);

	/* Before do_checkpoint, we should flip the nat_bit */

	ckpt->user_block_count = cpu_to_le64(user_block_count);
	ckpt->rsvd_segment_count = cpu_to_le32(rsvd_segment_count);
	ckpt->overprov_segment_count = cpu_to_le32(overprov_segment_count);

	ckpt->elapsed_time = cpu_to_le64(get_mtime(sbi));

    ckpt->checkpoint_ver = cpu_to_le64(++ckpt_ver);
	ckpt->valid_block_count = cpu_to_le64(sbi->total_valid_block_count);
	ckpt->checksum_offset = CHECKSUM_OFFSET;
	ckpt->sit_ver_bitmap_bytesize = cpu_to_le32((le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment_count_sit) / 2)
										* (sbi->blocks_per_seg / 8));
	ckpt->nat_ver_bitmap_bytesize = cpu_to_le32((le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment_count_nat) / 2)
										* (sbi->blocks_per_seg / 8));

	ckpt->free_segment_count = FREE_I(sbi)->free_segments;

	/**/
	curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	ckpt->cur_data_segno[0] = cpu_to_le32(curseg->segno);
	ckpt->cur_data_blkoff[0] = cpu_to_le16(curseg->next_blkoff);
	ckpt->alloc_type[0] = curseg->alloc_type;

	curseg = CURSEG_I(sbi, CURSEG_WARM_DATA);
	ckpt->cur_data_segno[1] = cpu_to_le32(curseg->segno);
	ckpt->cur_data_blkoff[1] = cpu_to_le16(curseg->next_blkoff);
	ckpt->alloc_type[1] = curseg->alloc_type;

	curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
	ckpt->cur_data_segno[2] = cpu_to_le32(curseg->segno);
	ckpt->cur_data_blkoff[2] = cpu_to_le16(curseg->next_blkoff);
	ckpt->alloc_type[2] = curseg->alloc_type;

	curseg = CURSEG_I(sbi, CURSEG_HOT_NODE);
	ckpt->cur_node_segno[0] = cpu_to_le32(curseg->segno);
	ckpt->cur_node_blkoff[0] = cpu_to_le16(curseg->next_blkoff);
	ckpt->alloc_type[3] = curseg->alloc_type;

	curseg = CURSEG_I(sbi, CURSEG_WARM_NODE);
	ckpt->cur_node_segno[1] = cpu_to_le32(curseg->segno);
	ckpt->cur_node_blkoff[1] = cpu_to_le16(curseg->next_blkoff);
	ckpt->alloc_type[4] = curseg->alloc_type;

	curseg = CURSEG_I(sbi, CURSEG_COLD_NODE);
	ckpt->cur_node_segno[2] = cpu_to_le32(curseg->segno);
	ckpt->cur_node_blkoff[2] = cpu_to_le16(curseg->next_blkoff);
	ckpt->alloc_type[5] = curseg->alloc_type;

	/******************************************************/
	ckpt->valid_node_count = cpu_to_le32(sbi->total_valid_node_count);
	ckpt->valid_inode_count = cpu_to_le32(sbi->total_valid_inode_count);

	/*data_sum_blks = 1;*/
	/*ckpt->ckpt_flags = cpu_to_le32(CP_COMPACT_SUM_FLAG | CP_UMOUNT_FLAG);*/
	data_sum_blks = NR_CURSEG_DATA_TYPE;
	ckpt->ckpt_flags = cpu_to_le32(CP_UMOUNT_FLAG);

	ckpt->cp_pack_start_sum = cpu_to_le32(1 + cp_payload_blks);
	ckpt->cp_pack_total_block_count = cpu_to_le32(2 + cp_payload_blks +
								data_sum_blks + NR_CURSEG_NODE_TYPE);

    get_sit_bitmap(sbi, __bitmap_ptr(sbi, SIT_BITMAP));
    get_nat_bitmap(sbi, __bitmap_ptr(sbi, NAT_BITMAP));

	crc32 = f2fs_cal_crc32(F2FS_SUPER_MAGIC, ckpt, le32_to_cpu(ckpt->checksum_offset));
    *((__le32 *)((unsigned char *)ckpt +
                le32_to_cpu(ckpt->checksum_offset)))
                = cpu_to_le32(crc32);

	/* cp pack 1 holds odd-numbered version, and cp pack 2 holds even-numbered version */
	start_blk = le32_to_cpu(F2FS_RAW_SUPER(sbi)->cp_blkaddr);
	if(!(ckpt_ver & 1))
		start_blk += sbi->blocks_per_seg;

	/* write cp1 of checkpoint pack */
	ret = dev_write(ckpt, start_blk++ * F2FS_BLKSIZE, F2FS_BLKSIZE);
	ASSERT(ret == 0);

	/* write cp payload */
	for (i = 1; i < 1 + cp_payload_blks; i++) {
		ret = dev_write((void *)(ckpt + i), start_blk++ * F2FS_BLKSIZE, F2FS_BLKSIZE);
		ASSERT(ret == 0);
	}

	/* write data summaries */
	write_normal_summaries(sbi, start_blk, CURSEG_HOT_DATA);
	start_blk += data_sum_blks;

	/* write node summaries */
	write_normal_summaries(sbi, start_blk, CURSEG_HOT_NODE);
	start_blk += NR_CURSEG_NODE_TYPE;

	/* write cp2 of checkpoint pack */
	ret = dev_write(ckpt, start_blk * F2FS_BLKSIZE, F2FS_BLKSIZE);
	ASSERT(ret == 0);

	return ret;
}
