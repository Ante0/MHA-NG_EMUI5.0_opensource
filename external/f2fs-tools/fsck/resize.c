/*resize.c
 *
 * Copyright (c) 2015 Jaegeuk Kim <jaegeuk@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "fsck.h"

struct f2fs_nat_block *nat_block;
struct f2fs_summary_block *summary_block;

static int get_new_sb(struct f2fs_sb_info *sbi, struct f2fs_super_block *sb, u_int32_t old_crc)
{
       u_int32_t crc = 0;
       u_int32_t zone_size_bytes, zone_align_start_offset;
       u_int32_t blocks_for_sit, blocks_for_nat, blocks_for_ssa;
       u_int32_t sit_segments, diff, total_meta_segments;
       u_int32_t total_valid_blks_available;
       u_int32_t sit_bitmap_size, max_sit_bitmap_size;
       u_int32_t max_nat_bitmap_size, max_nat_segments;
       u_int32_t log_sectorsize, log_sectors_per_block;

       /* here we need adjust sector size */
       log_sectorsize = log_base_2(config.sector_size);
       log_sectors_per_block = log_base_2(config.sectors_per_blk);
       set_sb(log_sectorsize, log_sectorsize);
       set_sb(log_sectors_per_block, log_sectors_per_block);

       u_int32_t segment_size_bytes = 1 << (get_sb(log_blocksize) +
                                       get_sb(log_blocks_per_seg));
       u_int32_t blks_per_seg = 1 << get_sb(log_blocks_per_seg);
       u_int32_t segs_per_zone = get_sb(segs_per_sec) * get_sb(secs_per_zone);

       set_sb(block_count, config.target_sectors >>
                               get_sb(log_sectors_per_block));

       zone_size_bytes = segment_size_bytes * segs_per_zone;
       zone_align_start_offset =
               (config.start_sector * config.sector_size +
               2 * F2FS_BLKSIZE + zone_size_bytes - 1) /
               zone_size_bytes * zone_size_bytes -
               config.start_sector * config.sector_size;

       set_sb(segment_count, (config.target_sectors * config.sector_size -
                               zone_align_start_offset) / segment_size_bytes);

       blocks_for_sit = ALIGN(get_sb(segment_count), SIT_ENTRY_PER_BLOCK);
       sit_segments = SEG_ALIGN(blocks_for_sit);
       set_sb(segment_count_sit, sit_segments * 2);
       set_sb(nat_blkaddr, get_sb(sit_blkaddr) +
                               get_sb(segment_count_sit) * blks_per_seg);

       total_valid_blks_available = (get_sb(segment_count) -
                       (get_sb(segment_count_ckpt) +
                       get_sb(segment_count_sit))) * blks_per_seg;
       blocks_for_nat = ALIGN(total_valid_blks_available, NAT_ENTRY_PER_BLOCK);
       set_sb(segment_count_nat, SEG_ALIGN(blocks_for_nat));

       sit_bitmap_size = ((get_sb(segment_count_sit) / 2) <<
                               get_sb(log_blocks_per_seg)) / 8;
       if (sit_bitmap_size > MAX_SIT_BITMAP_SIZE)
               max_sit_bitmap_size = MAX_SIT_BITMAP_SIZE;
       else
               max_sit_bitmap_size = sit_bitmap_size;

       /*
        * It should be reserved minimum 1 segment for nat.
        * When sit is too large, we should expand cp area. It requires more pages for cp.
        */
       if (max_sit_bitmap_size >
                       (CHECKSUM_OFFSET - sizeof(struct f2fs_checkpoint) + 65)) {
               max_nat_bitmap_size = CHECKSUM_OFFSET - sizeof(struct f2fs_checkpoint) + 1;
               set_sb(cp_payload, F2FS_BLK_ALIGN(max_sit_bitmap_size));
       } else {
               max_nat_bitmap_size = CHECKSUM_OFFSET - sizeof(struct f2fs_checkpoint) + 1
                       - max_sit_bitmap_size;
               set_sb(cp_payload, 0);
       }

       max_nat_segments = (max_nat_bitmap_size * 8) >>
                                       get_sb(log_blocks_per_seg);

       if (get_sb(segment_count_nat) > max_nat_segments)
               set_sb(segment_count_nat, max_nat_segments);

       set_sb(segment_count_nat, get_sb(segment_count_nat) * 2);

       set_sb(ssa_blkaddr, get_sb(nat_blkaddr) +
                               get_sb(segment_count_nat) * blks_per_seg);

       total_valid_blks_available = (get_sb(segment_count) -
                       (get_sb(segment_count_ckpt) +
                       get_sb(segment_count_sit) +
                       get_sb(segment_count_nat))) * blks_per_seg;

       blocks_for_ssa = total_valid_blks_available / blks_per_seg + 1;

       set_sb(segment_count_ssa, SEG_ALIGN(blocks_for_ssa));

       total_meta_segments = get_sb(segment_count_ckpt) +
               get_sb(segment_count_sit) +
               get_sb(segment_count_nat) +
               get_sb(segment_count_ssa);

       diff = total_meta_segments % segs_per_zone;
       if (diff)
               set_sb(segment_count_ssa, get_sb(segment_count_ssa) +
                       (segs_per_zone - diff));

       set_sb(main_blkaddr, get_sb(ssa_blkaddr) + get_sb(segment_count_ssa) *
                        blks_per_seg);

       set_sb(segment_count_main, get_sb(segment_count) -
                       (get_sb(segment_count_ckpt) +
                        get_sb(segment_count_sit) +
                        get_sb(segment_count_nat) +
                        get_sb(segment_count_ssa)));

       set_sb(section_count, get_sb(segment_count_main) /
                                               get_sb(segs_per_sec));

       set_sb(segment_count_main, get_sb(section_count) *
                                               get_sb(segs_per_sec));

       /* Let's determine the best reserved and overprovisioned space */
       config.new_overprovision = get_best_overprovision(sb);
       config.new_reserved_segments =
               (2 * (100 / config.new_overprovision + 1) + 6) *
                                               get_sb(segs_per_sec);

       if ((get_sb(segment_count_main) - 2) < config.new_reserved_segments ||
               get_sb(segment_count_main) * blks_per_seg >
                                               get_sb(block_count)) {
               MSG(-1, "\tError: Device size is not sufficient for F2FS volume,\
                       more segment needed =%u",
                       config.new_reserved_segments -
                       (get_sb(segment_count_main) - 2));
               return -1;
       }

       /* recalculate checksum for superblock, should use sb instead of sbi->raw_super*/
       crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, (unsigned char*)(sb),
						offsetof(struct f2fs_super_block, crc));
       set_sb(crc, crc);
       MSG(-1, "Info: update crc successfully (0x%x --> 0x%x)\n", old_crc, crc);

       return 0;
}

static void migrate_main(struct f2fs_sb_info *sbi,
               struct f2fs_super_block *new_sb, unsigned int offset)
{
       void *raw = calloc(BLOCK_SZ, 1);
       struct seg_entry *se;
       block_t from, to;
       int i, j, ret;
       struct f2fs_summary sum;

       ASSERT(raw != NULL);

       for (i = TOTAL_SEGS(sbi) - 1; i >= 0; i--) {
               se = get_seg_entry(sbi, i);
               if (!se->valid_blocks)
                       continue;

               for (j = sbi->blocks_per_seg - 1; j >= 0; j--) {
                       if (!f2fs_test_bit(j, (const char *)se->cur_valid_map))
                               continue;

                       from = START_BLOCK(sbi, i) + j;
                       ret = dev_read_block(raw, from);
                       ASSERT(ret >= 0);

                       to = from + offset;
                       ret = dev_write_block(raw, to);
                       ASSERT(ret >= 0);

                       get_sum_entry(sbi, from, &sum);

                       if (IS_DATASEG(se->type))
                               update_data_blkaddr(sbi, le32_to_cpu(sum.nid),
                                       le16_to_cpu(sum.ofs_in_node), to);
                       else
                               update_nat_blkaddr(sbi,
                                               le32_to_cpu(sum.nid), to);
               }
       }
       free(raw);
       DBG(0, "Info: Done to migrate data and node blocks\n");
}

static void build_res_meta(struct f2fs_sb_info *sbi,
               struct f2fs_super_block *sb, struct f2fs_super_block *new_sb)
{

       block_t block_off, block_addr;
       unsigned int segno, segnum;
       struct f2fs_nm_info *nm_i = NM_I(sbi);
       unsigned int nr_nat_blks, seg_off;
       int ret;

       /* here we have shrink nat */
       nr_nat_blks = get_newsb(segment_count_nat) *
				(1 << get_sb(log_blocks_per_seg) - 1);
       nat_block = (struct f2fs_nat_block *)calloc(BLOCK_SZ, nr_nat_blks);

       for (block_off = 0; block_off < nr_nat_blks; block_off++) {
               seg_off = block_off >> get_sb(log_blocks_per_seg);
               block_addr = (block_t)(get_sb(nat_blkaddr) +
                       (seg_off << get_sb(log_blocks_per_seg) << 1) +
                       (block_off & ((1 << get_sb(log_blocks_per_seg)) - 1)));

               if (f2fs_test_bit(block_off, nm_i->nat_bitmap))
                       block_addr += (1 << get_sb(log_blocks_per_seg));

               ret = dev_read_block(nat_block + block_off, block_addr);
               ASSERT(ret >= 0);
       }

       segnum = TOTAL_SEGS(sbi);
       summary_block = (struct f2fs_summary_block *)calloc(BLOCK_SZ, segnum);

       for (segno = 0; segno < segnum; segno++) {
               block_addr = get_sb(ssa_blkaddr)+ segno;
               ret = dev_read_block(summary_block + segno, block_addr);
               ASSERT(ret >= 0);
       }
}

static void migrate_nat_res_meta(struct f2fs_sb_info *sbi,
                       struct f2fs_super_block *sb, struct f2fs_super_block *new_sb)
{
       block_t block_off, block_addr;
       unsigned int nr_nat_blks, seg_off;
       u_int64_t nat_seg_addr=0;
       u_int8_t *nat_buf = NULL;
       u_int32_t blk_size, seg_size;
       int index, ret;

       nr_nat_blks = get_newsb(segment_count_nat) *
				(1 << get_sb(log_blocks_per_seg) - 1);

       blk_size = 1 << get_newsb(log_blocksize);
       seg_size = (1 << get_newsb(log_blocks_per_seg)) * blk_size;

       nat_buf = calloc(sizeof(u_int8_t), seg_size);
       nat_seg_addr = get_newsb(nat_blkaddr);
       nat_seg_addr *= blk_size;

       for (index = 0; index < get_newsb(segment_count_nat) / 2; index++) {
		ret = dev_fill(nat_buf, nat_seg_addr, seg_size);
		ASSERT(ret >= 0);
		nat_seg_addr = nat_seg_addr + (2 * seg_size);
       }

       free(nat_buf);

       for (block_off = 0; block_off < nr_nat_blks; block_off++) {
               seg_off = block_off >> get_newsb(log_blocks_per_seg);
               block_addr = (block_t)(get_newsb(nat_blkaddr) +
                       (seg_off << get_newsb(log_blocks_per_seg) << 1) +
                       (block_off & ((1 << get_newsb(log_blocks_per_seg)) - 1)));

               ret = dev_write_block(nat_block + block_off, block_addr);
               ASSERT(ret >= 0);
       }

       DBG(0, "Info: Done to migrate NAT blocks\n");
}

static void migrate_sit_res_meta(struct f2fs_sb_info *sbi,
                       struct f2fs_super_block *new_sb, unsigned int offset)
{
       struct sit_info *sit_i = SIT_I(sbi);
       unsigned int ofs = 0, pre_ofs = 0;
       unsigned int segno, index;
       struct f2fs_sit_block *sit_blk = calloc(BLOCK_SZ, 1);
       block_t sit_blks = get_newsb(segment_count_sit) <<
                                               (sbi->log_blocks_per_seg - 1);
       struct seg_entry *se;
       block_t blk_addr = 0;
       int ret;

       ASSERT(sit_blk);

       /* initialize with zeros */
       for (index = 0; index < sit_blks; index++) {
               ret = dev_write_block(sit_blk, get_newsb(sit_blkaddr) + index);
               ASSERT(ret >= 0);
               DBG(1, "Write zero sit: %x\n", get_newsb(sit_blkaddr) + index);
       }

       for (segno = 0; segno < TOTAL_SEGS(sbi); segno++) {
               struct f2fs_sit_entry *sit;

               se = get_seg_entry(sbi, segno);
               ofs = SIT_BLOCK_OFFSET(sit_i, segno + offset);

               if (ofs != pre_ofs) {
                       blk_addr = get_newsb(sit_blkaddr) + pre_ofs;
                       ret = dev_write_block(sit_blk, blk_addr);
                       ASSERT(ret >= 0);
                       DBG(1, "Write valid sit: %x\n", blk_addr);

                       pre_ofs = ofs;
                       memset(sit_blk, 0, BLOCK_SZ);
               }

               sit = &sit_blk->entries[SIT_ENTRY_OFFSET(sit_i, segno + offset)];
               memcpy(sit->valid_map, se->cur_valid_map, SIT_VBLOCK_MAP_SIZE);
               sit->vblocks = cpu_to_le16((se->type << SIT_VBLOCKS_SHIFT) |
                                                       se->valid_blocks);
       }

       blk_addr = get_newsb(sit_blkaddr) + ofs;
       ret = dev_write_block(sit_blk, blk_addr);
       DBG(1, "Write valid sit: %x\n", blk_addr);
       ASSERT(ret >= 0);

       free(sit_blk);
       DBG(0, "Info: Done to migrate SIT blocks\n");
}

static void migrate_ssa_res_meta(struct f2fs_sb_info *sbi,
               struct f2fs_super_block *sb, struct f2fs_super_block *new_sb, unsigned int offset)
{
       unsigned int segno, segnum;
       block_t block_addr;
       u_int8_t *zero_buff;
       int ret;

       segnum = get_newsb(segment_count_main);
       zero_buff = calloc(F2FS_BLKSIZE, 1);

       for (segno = 0; segno < segnum; segno++) {
               block_addr = get_newsb(ssa_blkaddr) + segno;

               if(segno < offset) {
                       ret = dev_write_block(zero_buff, block_addr);
                       ASSERT(ret >= 0);
               } else if (segno >= offset && segno < TOTAL_SEGS(sbi) + offset) {
                       ret = dev_write_block(summary_block + segno - offset, block_addr);
                       ASSERT(ret >= 0);
               } else {
                       ret = dev_write_block(zero_buff, block_addr);
                       ASSERT(ret >= 0);
               }
       }

       free(zero_buff);
       DBG(0, "Info: Done to migrate SSA blocks\n");
}

static void move_ssa(struct f2fs_sb_info *sbi, unsigned int segno,
                                       block_t new_sum_blk_addr)
{
       struct f2fs_summary_block *sum_blk;
       int type;

       sum_blk = get_sum_block(sbi, segno, &type);
       if (type < SEG_TYPE_MAX) {
               int ret;

               ret = dev_write_block(sum_blk, new_sum_blk_addr);
               ASSERT(ret >= 0);
               DBG(1, "Write summary block: (%d) segno=%x/%x --> (%d) %x\n",
                               type, segno, GET_SUM_BLKADDR(sbi, segno),
                               IS_SUM_NODE_SEG(sum_blk->footer),
                               new_sum_blk_addr);
       }
       if (type == SEG_TYPE_NODE || type == SEG_TYPE_DATA ||
                       type == SEG_TYPE_MAX) {
               free(sum_blk);
       }
}

static void migrate_ssa(struct f2fs_sb_info *sbi,
		struct f2fs_super_block *new_sb, unsigned int offset)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	block_t old_sum_blkaddr = get_sb(ssa_blkaddr);
	block_t new_sum_blkaddr = get_newsb(ssa_blkaddr);
	block_t end_sum_blkaddr = get_newsb(main_blkaddr); /*lint !e10 !e40 !e63 !e160 !e732 !e744*/
	block_t expand_sum_blkaddr = new_sum_blkaddr +
					TOTAL_SEGS(sbi) - offset;
	block_t blkaddr;
	int ret;
	void *zero_block = calloc(BLOCK_SZ, 1);
	ASSERT(zero_block); /*lint !e717*/

	if (offset && new_sum_blkaddr < old_sum_blkaddr + offset) {
		blkaddr = new_sum_blkaddr;
		while (blkaddr < end_sum_blkaddr) {
			if (blkaddr < expand_sum_blkaddr)
				move_ssa(sbi, offset++, blkaddr++);
			else {
				ret = dev_write_block(zero_block, blkaddr++); /*lint !e747*/
				ASSERT(ret >=0); /*lint !e717*/
			}
		}
	} else {
		blkaddr = end_sum_blkaddr - 1;
		offset = TOTAL_SEGS(sbi) - 1;
		while (blkaddr >= new_sum_blkaddr) {
			if (blkaddr >= expand_sum_blkaddr) {
				ret = dev_write_block(zero_block, blkaddr--); /*lint !e747*/
				ASSERT(ret >=0); /*lint !e717*/
			}
			else
				move_ssa(sbi, offset--, blkaddr--);
		}
	}

	DBG(0, "Info: Done to migrate SSA blocks: sum_blkaddr = 0x%x -> 0x%x\n",
						old_sum_blkaddr, new_sum_blkaddr);
	free(zero_block);
}

static int shrink_nats(struct f2fs_sb_info *sbi,
                               struct f2fs_super_block *new_sb)
{
       struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
       struct f2fs_nm_info *nm_i = NM_I(sbi);
       block_t old_nat_blkaddr = get_sb(nat_blkaddr);
       unsigned int nat_blocks;
       void *nat_block, *zero_block;
       int nid, ret, new_max_nid;
       pgoff_t block_off;
       pgoff_t block_addr;
       int seg_off;

       nat_block = malloc(BLOCK_SZ);
       ASSERT(nat_block);
       zero_block = calloc(BLOCK_SZ, 1);
       ASSERT(zero_block);

       nat_blocks = get_newsb(segment_count_nat) >> 1;
       nat_blocks = nat_blocks << get_sb(log_blocks_per_seg);
       new_max_nid = NAT_ENTRY_PER_BLOCK * nat_blocks;

       for (nid = nm_i->max_nid - 1; nid > new_max_nid; nid -= NAT_ENTRY_PER_BLOCK) {
               block_off = nid / NAT_ENTRY_PER_BLOCK;
               seg_off = block_off >> sbi->log_blocks_per_seg;
               block_addr = (pgoff_t)(old_nat_blkaddr +
                               (seg_off << sbi->log_blocks_per_seg << 1) +
                               (block_off & ((1 << sbi->log_blocks_per_seg) - 1)));

               if (f2fs_test_bit(block_off, nm_i->nat_bitmap))
                       block_addr += sbi->blocks_per_seg;

               ret = dev_read_block(nat_block, block_addr);
               ASSERT(ret >= 0);

               if (memcmp(zero_block, nat_block, BLOCK_SZ)) {
                       ret = -1;
                       goto not_avail;
               }
       }
       ret = 0;
       nm_i->max_nid = new_max_nid;
not_avail:
       free(nat_block);
       free(zero_block);
       return ret;
}

static void migrate_nat(struct f2fs_sb_info *sbi,
                       struct f2fs_super_block *new_sb)
{
       struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
       struct f2fs_nm_info *nm_i = NM_I(sbi);
       block_t old_nat_blkaddr = get_sb(nat_blkaddr);
       block_t new_nat_blkaddr = get_newsb(nat_blkaddr);
       unsigned int nat_blocks;
       void *nat_block;
       int nid, ret, new_max_nid;
       pgoff_t block_off;
       pgoff_t block_addr;
       int seg_off;

       nat_block = malloc(BLOCK_SZ);
       ASSERT(nat_block);

       for (nid = nm_i->max_nid - 1; nid >= 0; nid -= NAT_ENTRY_PER_BLOCK) {
               block_off = nid / NAT_ENTRY_PER_BLOCK;
               seg_off = block_off >> sbi->log_blocks_per_seg;
               block_addr = (pgoff_t)(old_nat_blkaddr +
                               (seg_off << sbi->log_blocks_per_seg << 1) +
                               (block_off & ((1 << sbi->log_blocks_per_seg) - 1)));

               if (f2fs_test_bit(block_off, nm_i->nat_bitmap))
                       block_addr += sbi->blocks_per_seg;

               ret = dev_read_block(nat_block, block_addr);
               ASSERT(ret >= 0);

               block_addr = (pgoff_t)(new_nat_blkaddr +
                               (seg_off << sbi->log_blocks_per_seg << 1) +
                               (block_off & ((1 << sbi->log_blocks_per_seg) - 1)));

               /* new bitmap should be zeros */
               ret = dev_write_block(nat_block, block_addr);
               ASSERT(ret >= 0);
       }
       /* zero out newly assigned nids */
       memset(nat_block, 0, BLOCK_SZ);
       nat_blocks = get_newsb(segment_count_nat) >> 1;
       nat_blocks = nat_blocks << get_sb(log_blocks_per_seg);
       new_max_nid = NAT_ENTRY_PER_BLOCK * nat_blocks;

       DBG(1, "Write NAT block: %x->%x, max_nid=%x->%x\n",
                       old_nat_blkaddr, new_nat_blkaddr,
                       get_sb(segment_count_nat),
                       get_newsb(segment_count_nat));

       for (nid = nm_i->max_nid; nid < new_max_nid;
                               nid += NAT_ENTRY_PER_BLOCK) {
               block_off = nid / NAT_ENTRY_PER_BLOCK;
               seg_off = block_off >> sbi->log_blocks_per_seg;
               block_addr = (pgoff_t)(new_nat_blkaddr +
                               (seg_off << sbi->log_blocks_per_seg << 1) +
                               (block_off & ((1 << sbi->log_blocks_per_seg) - 1)));
               ret = dev_write_block(nat_block, block_addr);
               ASSERT(ret >= 0);
               DBG(1, "Write NAT: %lx\n", block_addr);
       }
       DBG(0, "Info: Done to migrate NAT blocks\n");
}

static void migrate_sit(struct f2fs_sb_info *sbi,
               struct f2fs_super_block *new_sb, unsigned int offset)
{
       struct sit_info *sit_i = SIT_I(sbi);
       unsigned int ofs = 0, pre_ofs = 0;
       unsigned int segno, index;
       struct f2fs_sit_block *sit_blk = calloc(BLOCK_SZ, 1);
       block_t sit_blks = get_newsb(segment_count_sit) <<
                                               (sbi->log_blocks_per_seg - 1);
       struct seg_entry *se;
       block_t blk_addr = 0;
       int ret;

       ASSERT(sit_blk);

       /* initialize with zeros */
       for (index = 0; index < sit_blks; index++) {
               ret = dev_write_block(sit_blk, get_newsb(sit_blkaddr) + index);
               ASSERT(ret >= 0);
               DBG(1, "Write zero sit: %x\n", get_newsb(sit_blkaddr) + index);
       }

       for (segno = 0; segno < TOTAL_SEGS(sbi); segno++) {
               struct f2fs_sit_entry *sit;

               se = get_seg_entry(sbi, segno);
               if (segno < offset) {
                       ASSERT(se->valid_blocks == 0);
                       continue;
               }

               ofs = SIT_BLOCK_OFFSET(sit_i, segno - offset);

               if (ofs != pre_ofs) {
                       blk_addr = get_newsb(sit_blkaddr) + pre_ofs;
                       ret = dev_write_block(sit_blk, blk_addr);
                       ASSERT(ret >= 0);
                       DBG(1, "Write valid sit: %x\n", blk_addr);

                       pre_ofs = ofs;
                       memset(sit_blk, 0, BLOCK_SZ);
               }

               sit = &sit_blk->entries[SIT_ENTRY_OFFSET(sit_i, segno - offset)];
               memcpy(sit->valid_map, se->cur_valid_map, SIT_VBLOCK_MAP_SIZE);
               sit->vblocks = cpu_to_le16((se->type << SIT_VBLOCKS_SHIFT) |
                                                       se->valid_blocks);
       }
       blk_addr = get_newsb(sit_blkaddr) + ofs;
       ret = dev_write_block(sit_blk, blk_addr);
       DBG(1, "Write valid sit: %x\n", blk_addr);
       ASSERT(ret >= 0);

       free(sit_blk);
       DBG(0, "Info: Done to migrate SIT blocks\n");
}

static void rebuild_checkpoint(struct f2fs_sb_info *sbi,
                       struct f2fs_super_block *new_sb, unsigned int offset, int reserved_meta)
{
       struct f2fs_checkpoint *cp = F2FS_CKPT(sbi);
       struct f2fs_checkpoint *new_cp;
       struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
       unsigned int free_segment_count, new_segment_count;
       block_t new_cp_blks = 1 + get_newsb(cp_payload);
       block_t orphan_blks = 0;
       block_t new_cp_blk_no, old_cp_blk_no;
       u_int32_t crc = 0;
       void *buf;
       int i, ret;

       new_cp = calloc(new_cp_blks * BLOCK_SZ, 1);
       ASSERT(new_cp);

       buf = malloc(BLOCK_SZ);
       ASSERT(buf);

       /* ovp / free segments */
       set_cp(rsvd_segment_count, config.new_reserved_segments);
       set_cp(overprov_segment_count, (get_newsb(segment_count_main) -
                        get_cp(rsvd_segment_count)) *
                        config.new_overprovision / 100);

       set_cp(overprov_segment_count, get_cp(overprov_segment_count) +
                                               get_cp(rsvd_segment_count));

       free_segment_count = get_free_segments(sbi);
       new_segment_count = get_newsb(segment_count_main) -
                                       get_sb(segment_count_main);

       set_cp(free_segment_count, free_segment_count + new_segment_count);
       set_cp(user_block_count, ((get_newsb(segment_count_main) -
                       get_cp(overprov_segment_count)) * config.blks_per_seg));

       if (is_set_ckpt_flags(cp, CP_ORPHAN_PRESENT_FLAG))
               orphan_blks = __start_sum_addr(sbi) - 1;

       set_cp(cp_pack_start_sum, 1 + get_newsb(cp_payload));
       set_cp(cp_pack_total_block_count, 8 + orphan_blks + get_newsb(cp_payload));

       /* cur->segno - offset */
       if(!reserved_meta) {
		for (i = 0; i < NO_CHECK_TYPE; i++) {
			if (i < CURSEG_HOT_NODE) {
				set_cp(cur_data_segno[i],
					CURSEG_I(sbi, i)->segno - offset);
			} else {
				int n = i - CURSEG_HOT_NODE;

				set_cp(cur_node_segno[n],
					CURSEG_I(sbi, i)->segno - offset);
			}
		}
       } else {
		for (i = 0; i < NO_CHECK_TYPE; i++) {
			if (i < CURSEG_HOT_NODE) {
				set_cp(cur_data_segno[i],
				CURSEG_I(sbi, i)->segno + offset);
			} else {
				int n = i - CURSEG_HOT_NODE;

				set_cp(cur_node_segno[n],
					CURSEG_I(sbi, i)->segno + offset);
			}
		}
       }

       /* sit / nat ver bitmap bytesize */
       set_cp(sit_ver_bitmap_bytesize,
                       ((get_newsb(segment_count_sit) / 2) <<
                       get_newsb(log_blocks_per_seg)) / 8);
       set_cp(nat_ver_bitmap_bytesize,
                       ((get_newsb(segment_count_nat) / 2) <<
                       get_newsb(log_blocks_per_seg)) / 8);

       memcpy(new_cp, cp, (unsigned char *)cp->sit_nat_version_bitmap -
                                               (unsigned char *)cp);

       crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, new_cp, CHECKSUM_OFFSET);
       *((__le32 *)((unsigned char *)new_cp + CHECKSUM_OFFSET)) = cpu_to_le32(crc);

       /* Write a new checkpoint in the other set */
       new_cp_blk_no = old_cp_blk_no = get_sb(cp_blkaddr);
       if (sbi->cur_cp == 2)
               old_cp_blk_no += 1 << get_sb(log_blocks_per_seg);
       else
               new_cp_blk_no += 1 << get_sb(log_blocks_per_seg);

       /* write first cp */
       ret = dev_write_block(new_cp, new_cp_blk_no++);
       ASSERT(ret >= 0);

       memset(buf, 0, BLOCK_SZ);
       for (i = 0; i < get_newsb(cp_payload); i++) {
               ret = dev_write_block(buf, new_cp_blk_no++);
               ASSERT(ret >= 0);
       }

       for (i = 0; i < orphan_blks; i++) {
               block_t orphan_blk_no = old_cp_blk_no + 1 + get_sb(cp_payload);

               ret = dev_read_block(buf, orphan_blk_no++);
               ASSERT(ret >= 0);

               ret = dev_write_block(buf, new_cp_blk_no++);
               ASSERT(ret >= 0);
       }

       /* update summary blocks having nullified journal entries */
       for (i = 0; i < NO_CHECK_TYPE; i++) {
               struct curseg_info *curseg = CURSEG_I(sbi, i);

               ret = dev_write_block(curseg->sum_blk, new_cp_blk_no++);
               ASSERT(ret >= 0);
       }

       /* write the last cp */
       ret = dev_write_block(new_cp, new_cp_blk_no++);
       ASSERT(ret >= 0);

       /* disable old checkpoint */
       memset(buf, 0, BLOCK_SZ);
       ret = dev_write_block(buf, old_cp_blk_no);
       ASSERT(ret >= 0);

       free(buf);
       free(new_cp);
       DBG(0, "Info: Done to rebuild checkpoint blocks\n");
}

static void rebuild_superblock(struct f2fs_sb_info *sbi,
                               struct f2fs_super_block *new_sb)
{
       int index, ret;
       u_int8_t *buf;

       buf = calloc(BLOCK_SZ, 1);

       memcpy(buf + F2FS_SUPER_OFFSET, new_sb, sizeof(*new_sb));
       for (index = 0; index < 2; index++) {
               ret = dev_write_block(buf, index);
               ASSERT(ret >= 0);
       }
       free(buf);
       DBG(0, "Info: Done to rebuild superblock\n");
}

int f2fs_resize(struct f2fs_sb_info *sbi)
{
       struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
       struct f2fs_super_block new_sb_raw;
       struct f2fs_super_block *new_sb = &new_sb_raw;
       block_t end_blkaddr, old_main_blkaddr, new_main_blkaddr;
       unsigned int offset, offset_seg = 0;
       int err = -1, reserved_meta = 0;

       /* flush NAT/SIT journal entries */
       flush_journal_entries(sbi);

       memcpy(new_sb, F2FS_RAW_SUPER(sbi), sizeof(*new_sb));
       if (get_new_sb(sbi, new_sb, get_sb(crc)))
               return -1;

       /* check nat availability */
       if (get_sb(segment_count_nat) > get_newsb(segment_count_nat)) {
               err = shrink_nats(sbi, new_sb);
               if (err) {
                       MSG(0, "\tError: Failed to shrink NATs\n");
                       return err;
               }
       }

       config.dbg_lv = 1;
       print_raw_sb_info(sb);
       print_raw_sb_info(new_sb);
       config.dbg_lv = 0;

       old_main_blkaddr = get_sb(main_blkaddr);
       new_main_blkaddr = get_newsb(main_blkaddr);
       offset = new_main_blkaddr - old_main_blkaddr;
       end_blkaddr = (get_sb(segment_count_main) <<
			get_sb(log_blocks_per_seg)) + get_sb(main_blkaddr);

       /* Here we need to be compatible with old version */
       if (old_main_blkaddr > new_main_blkaddr) {
		if (get_sb(segment_count) < get_newsb(segment_count)) {
			reserved_meta = 1;
			MSG(0, "\tInfo: Support reserved space userdata\n");
			offset = old_main_blkaddr - new_main_blkaddr;
			offset_seg = offset >> get_sb(log_blocks_per_seg);
			goto old_version_userdata;
		}

		MSG(0, "\tError: Support resize to expand only\n");
		return -1;
       }

       err = -EAGAIN;
       offset = new_main_blkaddr - old_main_blkaddr;

       if (new_main_blkaddr < end_blkaddr) {
               err = f2fs_defragment(sbi, old_main_blkaddr, offset,
                                               new_main_blkaddr, 0);
		if (!err)
			offset_seg = offset >> get_sb(log_blocks_per_seg);
		MSG(0, "Try to do defragment: %s\n", err ? "Skip": "Done");
       }
       /* move whole data region */
       if (err)
               migrate_main(sbi, new_sb, offset);

       migrate_ssa(sbi, new_sb, offset_seg);
       migrate_nat(sbi, new_sb);
       migrate_sit(sbi, new_sb, offset_seg);

old_version_userdata:
       if (reserved_meta) {
		build_res_meta(sbi, sb, new_sb);
		migrate_sit_res_meta(sbi, new_sb, offset_seg);
		migrate_nat_res_meta(sbi, sb, new_sb);
		migrate_ssa_res_meta(sbi, sb, new_sb, offset_seg);

		free(nat_block);
		free(summary_block);
       }

       rebuild_checkpoint(sbi, new_sb, offset_seg, reserved_meta);
       config.dbg_lv = 1;
       print_ckpt_info(sbi);
       config.dbg_lv = 0;
       rebuild_superblock(sbi, new_sb);
       return 0;
}
