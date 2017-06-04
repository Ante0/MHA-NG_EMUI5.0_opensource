#ifndef _SEGMENT_H
#define _SEGMENT_H

#include <f2fs_fs.h>
#include "sload.h"
#include "f2fs.h"
#include "bit_operations.h"
#include <sys/time.h>

enum {
	ALLOC_RIGHT = 0,
	ALLOC_LEFT
};

struct free_segmap_info {
	unsigned int start_segno;
	unsigned int free_segments;
	unsigned int free_sections;
	unsigned long *free_segmap;
	unsigned long *free_secmap;
};

#define MAIN_SEGS(sbi) (SM_I(sbi)->main_segments)
#define MAIN_SECS(sbi) (sbi->total_sections)
#define MAIN_BLKADDR(sbi)	(SM_I(sbi)->main_blkaddr)
#define GET_SUM_BLOCK(sbi, segno)	\
		((sbi->sm_info->ssa_blkaddr) + segno)

#define SEG0_BLKADDR(sbi)   (SM_I(sbi)->seg0_blkaddr)
#define NEXT_FREE_BLKADDR(sbi, curseg)	\
		(START_BLOCK(sbi, curseg->segno) + curseg->next_blkoff)

#define BITS_PER_BYTE 8
#define DIV_ROUND_UP(x, y)	(((x) + (y) -1) / (y))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(unsigned long))
#define f2fs_bitmap_size(nr) \
		(BITS_TO_LONGS(nr) * sizeof(unsigned long))

#define GET_SECNO(sbi, segno)	\
		((segno) / sbi->segs_per_sec)

static inline void check_seg_range(struct f2fs_sb_info *sbi, unsigned int segno)
{
    unsigned int end_segno = SM_I(sbi)->segment_count - 1;
    ASSERT(segno <= end_segno);
}

static inline void __set_test_and_inuse(struct f2fs_sb_info *sbi,
			unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno = segno / sbi->segs_per_sec;

	if (!test_and_set_bit(segno, (char *)free_i->free_segmap)) {
		free_i->free_segments--;
		if (!test_and_set_bit(secno, (char *)free_i->free_secmap))
			free_i->free_sections--;
	}
}

static inline void __set_free(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno = segno / sbi->segs_per_sec;
	unsigned int start_segno = secno * sbi->segs_per_sec;
	unsigned int next;

	clear_bit(segno, free_i->free_segmap);
	free_i->free_segments++;

	/* Find the 1st 1 */
	next = find_next_bit_le_sload((const char *)free_i->free_segmap,
					start_segno + sbi->segs_per_sec, start_segno);

	if (next >= start_segno + sbi->segs_per_sec) {
		clear_bit(secno, free_i->free_secmap);
		free_i->free_sections++;
	}
}
static inline void set_summary(struct f2fs_summary *sum, nid_t nid,
				unsigned int ofs_in_node, unsigned char version)
{
	sum->nid = cpu_to_le32(nid);
	sum->ofs_in_node = cpu_to_le16(ofs_in_node);
	sum->version = version;
}

static inline struct sec_entry *get_sec_entry(struct f2fs_sb_info *sbi,
				unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	return &sit_i->sec_entries[GET_SECNO(sbi, segno)];
}

static inline struct seg_entry *get_seg_entry(struct f2fs_sb_info *sbi,
				        unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	return &sit_i->sentries[segno];
}

static inline void seg_info_from_raw_sit(struct seg_entry *se,
        struct f2fs_sit_entry *raw_sit)
{
    se->valid_blocks = GET_SIT_VBLOCKS(raw_sit);
    se->ckpt_valid_blocks = GET_SIT_VBLOCKS(raw_sit);
    memcpy(se->cur_valid_map, raw_sit->valid_map, SIT_VBLOCK_MAP_SIZE);
    memcpy(se->ckpt_valid_map, raw_sit->valid_map, SIT_VBLOCK_MAP_SIZE);
    se->type = GET_SIT_TYPE(raw_sit);
    se->orig_type = GET_SIT_TYPE(raw_sit);
    se->mtime = le64_to_cpu(raw_sit->mtime);
}

static inline void get_sit_bitmap(struct f2fs_sb_info *sbi,
        void *dst_addr)
{
    struct sit_info *sit_i = SIT_I(sbi);
    memcpy(dst_addr, sit_i->sit_bitmap, sit_i->bitmap_size);
}

static inline unsigned long long get_mtime(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct timeval time;

	gettimeofday(&time, (struct timezone *)NULL);
	return sit_i->elapsed_time + time.tv_sec - sit_i->mounted_time;
}

block_t allocate_data_block(struct f2fs_sb_info *sbi,
		struct dnode_of_data *dn, struct f2fs_node *node_page, int type);
void remove_sits_in_journal(struct f2fs_sb_info *sbi);
int build_segment_manager(struct f2fs_sb_info *sbi);
void write_normal_summaries(struct f2fs_sb_info *sbi, block_t blkaddr, int type);
void flush_sit_entries(struct f2fs_sb_info *sbi);
inline void get_sit_bitmap(struct f2fs_sb_info *sbi, void *dst_addr);
#endif
