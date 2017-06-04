#include <f2fs_fs.h>
#include "sload.h"
#include "node.h"
#include "f2fs.h"
#include "segment.h"
#include "bit_operations.h"

#define MAIN_AREA_START 4096
#define NAT_AREA_START 2560

static bool __mark_sit_entry_dirty(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);

	if (!test_and_set_bit(segno, (char *)sit_i->dirty_sentries_bitmap)) {
		sit_i->dirty_sentries++;
		return false;
	}
	return true;
}

static struct f2fs_sit_block *get_current_sit_page(struct f2fs_sb_info *sbi,
                        unsigned int segno)
{
    struct sit_info *sit_i = SIT_I(sbi);
    unsigned int offset = SIT_BLOCK_OFFSET(sit_i, segno);
    block_t blk_addr = sit_i->sit_base_addr + offset;
    struct f2fs_sit_block *sit_blk = calloc(BLOCK_SZ, 1);
    int ret;

	if (sit_blk == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		return NULL;
	}
    check_seg_range(sbi, segno);

    /* calculate sit block address */
    if (f2fs_test_bit(offset, sit_i->sit_bitmap))
        blk_addr += sit_i->sit_blocks;

    ret = dev_read_block(sit_blk, blk_addr);
	if (ret < 0) {
		ERR_MSG("\tError: Fail to Read block\n");
		free(sit_blk);
		sit_blk = NULL;
	}

    return sit_blk;
}

static void reset_curseg(struct f2fs_sb_info *sbi, int type)
{
    struct curseg_info *curseg = CURSEG_I(sbi, type);
    struct summary_footer *sum_footer;
    struct seg_entry *se;

    curseg->segno = curseg->next_segno;
    curseg->zone = GET_ZONENO_FROM_SEGNO(sbi, curseg->segno);
    curseg->next_blkoff = 0;
    curseg->next_segno = NULL_SEGNO;

    sum_footer = &(curseg->sum_blk->footer);
    memset(sum_footer, 0, sizeof(struct summary_footer));
    if (IS_DATASEG(type))
        SET_SUM_TYPE(sum_footer, SUM_TYPE_DATA);
    if (IS_NODESEG(type))
        SET_SUM_TYPE(sum_footer, SUM_TYPE_NODE);
    se = get_seg_entry(sbi, curseg->segno);
    se->type = type;
}

static pgoff_t current_sit_addr(struct f2fs_sb_info *sbi,
				unsigned int start)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int offset = SIT_BLOCK_OFFSET(sit_i, start);
	block_t blk_addr = sit_i->sit_base_addr + offset;

	check_seg_range(sbi, start);

	if (f2fs_test_bit(offset, sit_i->sit_bitmap))
		blk_addr += sit_i->sit_blocks;
	return blk_addr;
}

static void __add_sum_entry(struct f2fs_sb_info *sbi, int type,
				struct f2fs_summary *sum)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	void *addr = curseg->sum_blk;
	addr += curseg->next_blkoff * sizeof(struct f2fs_summary);
	memcpy(addr, sum, sizeof(struct f2fs_summary));
}

static void check_block_count(struct f2fs_sb_info *sbi,
        unsigned int segno, struct f2fs_sit_entry *raw_sit)
{
    struct f2fs_sm_info *sm_info = SM_I(sbi);
    unsigned int end_segno = sm_info->segment_count - 1;
    int valid_blocks = 0;
    unsigned int i;

    /* check segment usage */
    if (GET_SIT_VBLOCKS(raw_sit) > sbi->blocks_per_seg)
        ASSERT_MSG("Invalid SIT vblocks: segno=0x%x, %u",
                segno, GET_SIT_VBLOCKS(raw_sit));

    /* check boundary of a given segment number */
    if (segno > end_segno)
        ASSERT_MSG("Invalid SEGNO: 0x%x", segno);

    /* check bitmap with valid block count */
    for (i = 0; i < SIT_VBLOCK_MAP_SIZE; i++)
        valid_blocks += get_bits_in_byte(raw_sit->valid_map[i]);

    if (GET_SIT_VBLOCKS(raw_sit) != valid_blocks)
        ASSERT_MSG("Wrong SIT valid blocks: segno=0x%x, %u vs. %u",
                segno, GET_SIT_VBLOCKS(raw_sit), valid_blocks);

    if (GET_SIT_TYPE(raw_sit) >= NO_CHECK_TYPE)
        ASSERT_MSG("Wrong SIT type: segno=0x%x, %u",
                segno, GET_SIT_TYPE(raw_sit));
}

static pgoff_t next_sit_addr(struct f2fs_sb_info *sbi,
				pgoff_t block_addr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	block_addr -= sit_i->sit_base_addr;

	if (block_addr < sit_i->sit_blocks)
		block_addr += sit_i->sit_blocks;
	else
		block_addr -= sit_i->sit_blocks;

	return block_addr + sit_i->sit_base_addr;
}

static int build_free_segmap(struct f2fs_sb_info *sbi)
{
	struct free_segmap_info *free_i;
	unsigned int bitmap_size, sec_bitmap_size;

	free_i = malloc(sizeof(struct free_segmap_info));

	if (!free_i)
		return -ENOMEM;

	SM_I(sbi)->free_info = free_i;

	/* Attention! bitmap_size is caculated by 'unsigned long' */
	bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));
	free_i->free_segmap = malloc(bitmap_size);

	if (!free_i->free_segmap)
		return -ENOMEM;

	sec_bitmap_size = f2fs_bitmap_size(MAIN_SECS(sbi));
	free_i->free_secmap = malloc(sec_bitmap_size);

	if (!free_i->free_secmap)
		return -ENOMEM;

	memset(free_i->free_segmap, 0xff, bitmap_size);
	memset(free_i->free_secmap, 0xff, sec_bitmap_size);

	free_i->start_segno = GET_SEGNO_FROM_SEG0(sbi, MAIN_BLKADDR(sbi));
	free_i->free_segments = 0;
	free_i->free_sections = 0;

	return 0;
}

static void init_free_segmap(struct f2fs_sb_info *sbi)
{
	unsigned int start;
	int type;

	for (start = 0; start < MAIN_SEGS(sbi); start++) {
		struct seg_entry *sentry = get_seg_entry(sbi, start);
		if (!sentry->valid_blocks) {
			__set_free(sbi, start);
		}
	}

	for (type = CURSEG_HOT_DATA; type <= CURSEG_COLD_NODE; type++) {
		struct curseg_info *curseg_t = CURSEG_I(sbi, type);
		__set_test_and_inuse(sbi, curseg_t->segno);
	}
}

static inline void __set_inuse(struct f2fs_sb_info *sbi,
			unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno = segno / sbi->segs_per_sec;
	set_bit(segno, free_i->free_segmap);
	free_i->free_segments--;
	if (!test_and_set_bit(secno, (char *)free_i->free_secmap))
		free_i->free_sections--;
}
static void get_new_segment(struct f2fs_sb_info *sbi,
				unsigned int *newseg, bool new_sec, int dir)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int segno, secno, zoneno;
	unsigned int total_zones = MAIN_SECS(sbi) / sbi->secs_per_zone;
	unsigned int hint = *newseg / sbi->segs_per_sec;
	unsigned int old_zoneno = GET_ZONENO_FROM_SEGNO(sbi, *newseg);
	unsigned int left_start = hint;
	bool init = true;
	int go_left = 0;
	int i;

	if (!new_sec && ((*newseg + 1) % sbi->segs_per_sec)) {
		segno = find_next_zero_bit_le_sload((char *)free_i->free_segmap,
						MAIN_SEGS(sbi), *newseg + 1);
		if (segno - *newseg < sbi->segs_per_sec -
				(*newseg % sbi->segs_per_sec))
			goto got_it;
	}
find_other_zone:
	secno = find_next_zero_bit_le_sload((char *)free_i->free_secmap,
									MAIN_SECS(sbi), hint);
	if (secno >= MAIN_SECS(sbi)) {
		if (dir == ALLOC_RIGHT) {
			secno = find_next_zero_bit_le_sload((char *)free_i->free_secmap,
					MAIN_SECS(sbi), 0);

			ASSERT(secno >= MAIN_SECS(sbi));
		} else {
			go_left = 1;
			left_start = hint - 1;
		}
	}
	if (go_left == 0)
		goto skip_left;

	while (test_bit(left_start, free_i->free_secmap)) {
		if (left_start > 0) {
			left_start --;
			continue;
		}
		left_start = find_next_zero_bit_le_sload((char *)free_i->free_secmap,
						MAIN_SECS(sbi), 0);
		ASSERT(left_start >= MAIN_SECS(sbi));
		break;
	}
	secno = left_start;
skip_left:
	hint = secno;
	segno = secno * sbi->segs_per_sec;
	zoneno = secno / sbi->secs_per_zone;

	/* Give up on finding another zone */
	if (!init)
		goto got_it;
	if (sbi->secs_per_zone == 1)
		goto got_it;
	if (zoneno == old_zoneno)
		goto got_it;

	if (dir == ALLOC_LEFT) {
		if (!go_left && zoneno + 1 >= total_zones)
			goto got_it;
		if (go_left && zoneno == 0)
			goto got_it;
	}

	for (i = 0; i < NR_CURSEG_TYPE; i++)
		if (CURSEG_I(sbi, i)->zone == zoneno)
			break;

	if (i < NR_CURSEG_TYPE) {
		/* Zone is in user, try another */
		if (go_left)
			hint = zoneno * sbi->secs_per_zone -1;
		else if (zoneno + 1 >= total_zones)
			hint = 0;
		else
			hint = (zoneno + 1) * sbi->secs_per_zone;
		init = false;
		goto find_other_zone;
	}
got_it:
	ASSERT(!test_bit(segno, free_i->free_segmap));
	__set_inuse(sbi, segno);
	*newseg = segno;
}

static void write_sum_page(struct f2fs_summary_block *sum_blk, block_t blk_addr)
{
	int ret;
	ret = dev_write_block(sum_blk, blk_addr);
	ASSERT(ret >= 0);
}

static char data_type[6][20] ={"CURSEG_HOT_DATA", "CURSEG_WARM_DATA", "CURSEG_COLD_DATA",
	"CURSEG_HOT_NODE", "CURSEG_WARM_NODE", "CURSEG_COLD_NODE"};
static void allocate_segment(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int segno = curseg->segno;
	int dir = ALLOC_LEFT;

	write_sum_page(curseg->sum_blk,
				GET_SUM_BLOCK(sbi, segno));

	if (type == CURSEG_WARM_DATA || type == CURSEG_COLD_DATA)
		dir = ALLOC_RIGHT;

	/*
	if (test_opt(sbi, NOHEAP))
		dir = ALLOC_RIGHT;
	*/

	MSG(2, "type: %s change, From %d", data_type[type] + 7, segno);
	get_new_segment(sbi, &segno, false, dir);
	MSG(2, " to %d\n", segno);
	curseg->next_segno = segno;
	reset_curseg(sbi, type);
	curseg->alloc_type = LFS;
}

static bool __has_curseg_space(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	if (curseg->next_blkoff < sbi->blocks_per_seg)
		return true;
	return false;
}

/* Update the sit_entry to the related SIT segment */
static void update_sit(struct f2fs_sb_info *sbi, unsigned int segno)
{
	block_t curr_addr, next_addr;
	struct f2fs_sit_block *sit_block;
	struct f2fs_sit_entry *sit_entry;
	int off_in_sit_block;
	struct seg_entry *se;
	unsigned short raw_vblocks;
	unsigned int block_off = SIT_BLOCK_OFFSET(sit_i, segno);

    struct f2fs_sm_info *sm_info = SM_I(sbi);
    struct sit_info *sit_i = SIT_I(sbi);
	int ret;

	se = get_seg_entry(sbi, segno);

	curr_addr = current_sit_addr(sbi, segno);
	next_addr = next_sit_addr(sbi, curr_addr);

	sit_block = calloc(BLOCK_SZ, 1);
	ASSERT(sit_block);

	if (f2fs_test_bit(block_off, sm_info->flip_bitmap))
		ret = dev_read_block(sit_block, next_addr);
	else
		ret = dev_read_block(sit_block, curr_addr);
	ASSERT(ret >= 0);

	off_in_sit_block = SIT_ENTRY_OFFSET(sit_i, segno);
	sit_entry = &(sit_block->entries[off_in_sit_block]);

	/* seg_info to raw sit */
	raw_vblocks = (se->type << SIT_VBLOCKS_SHIFT) | se->valid_blocks;
	sit_entry->vblocks = raw_vblocks;

	memcpy(sit_entry->valid_map, se->cur_valid_map, SIT_VBLOCK_MAP_SIZE);
	sit_entry->mtime = cpu_to_le64(se->mtime);

	ret = dev_write_block(sit_block, next_addr);
	ASSERT(ret >= 0);
	/* Update the sit_entry done */

	/* Update the flip_bitmap */
	f2fs_set_bit(block_off, sm_info->flip_bitmap);
	MSG(2, "Update the %d SIT blocks\n", block_off);

}
static void update_sit_entry(struct f2fs_sb_info *sbi, block_t blkaddr, int del)
{
	struct seg_entry *se;
	unsigned int segno, offset;
	long int new_vblocks;
	segno = GET_SEGNO(sbi, blkaddr);

	se = get_seg_entry(sbi, segno);
	new_vblocks = se->valid_blocks + del;
	offset = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

	se->valid_blocks = new_vblocks;
	/*FIXME:Attention! Which time is necessary */
	se->mtime = get_mtime(sbi);
	MSG(3, "segno(%d)'s mtime:%llx\n", segno, se->mtime);
	SIT_I(sbi)->max_mtime = se->mtime;

	/* Update valid block bitmap */
	if (del > 0) {
		if (f2fs_test_and_set_bit(offset, (char *)se->cur_valid_map))
			ERR_MSG("Wrong se->bitmap\n");
	} else {
		if (!f2fs_test_and_clear_bit(offset, (char *)se->cur_valid_map))
			ERR_MSG("Wrong se->bitmap\n");
	}

	__mark_sit_entry_dirty(sbi, segno);

	SIT_I(sbi)->written_valid_blocks += del;
	if (sbi->segs_per_sec > 1)
		get_sec_entry(sbi, segno)->valid_blocks += del;
}

static void __refresh_next_blkoff(struct curseg_info *seg)
{
	seg->next_blkoff++;
}

block_t allocate_data_block(struct f2fs_sb_info *sbi,
				struct dnode_of_data *dn, struct f2fs_node *node_page, int type)
{

	struct curseg_info *curseg;
	block_t new_blkaddr;
	struct f2fs_summary sum;
	struct node_info ni;

	block_t valid_block_count;

	/* Init the SSA entry */
	valid_block_count = sbi->total_valid_block_count + 1;
	if (valid_block_count > sbi->user_block_count) {
		ERR_MSG("\t No space left\n");
		ASSERT(0);
	}

	get_node_info(sbi, dn->nid, &ni);

	if (dn) {
		if (IS_NODESEG(type))
			set_summary(&sum, dn->nid, 0, 0);
		else if(IS_DATASEG(type))
			set_summary(&sum, dn->nid, dn->ofs_in_node, ni.version);
		else 
			ERR_MSG("\tError type\n");
	}

	curseg = CURSEG_I(sbi, type);
	new_blkaddr = NEXT_FREE_BLKADDR(sbi, curseg);
	update_sit_entry(sbi, new_blkaddr, 1);

	__add_sum_entry(sbi, type, &sum);
	__refresh_next_blkoff(curseg);

	if (!__has_curseg_space(sbi, type)) {
		allocate_segment(sbi, type);
	}
	sbi->total_valid_block_count += 1;
	if (IS_NODESEG(type)) {
		sbi->total_valid_node_count += 1;
		if (node_page)
			fill_node_footer_blkaddr(node_page, NEXT_FREE_BLKADDR(sbi, curseg));
		if (IS_INODE(node_page)) {
			sbi->total_valid_inode_count += 1;
		}
	}
	/* Update inode i_blocks here*/
	dn->inode_page->i.i_blocks += 1;

	return new_blkaddr;
}

void remove_sits_in_journal(struct f2fs_sb_info *sbi)
{
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
	struct f2fs_journal *journal = &curseg->sum_blk->journal;
	int i;

	for (i = sits_in_cursum(journal) - 1; i >= 0; i --) {
		unsigned int segno;
		segno = le32_to_cpu(segno_in_journal(journal, i));
		__mark_sit_entry_dirty(sbi, segno);
	}
	journal->n_sits = 0;
}

static void read_compacted_summaries(struct f2fs_sb_info *sbi)
{
    struct curseg_info *curseg;
    unsigned int i, j, offset;
    struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
    block_t start;
    char *kaddr;
    int ret;

    start = start_sum_block(sbi);

    kaddr = (char *)malloc(PAGE_SIZE);
	ASSERT(kaddr);
    ret = dev_read_block(kaddr, start++);
    ASSERT(ret >= 0);

    curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
    memcpy(&curseg->sum_blk->journal.n_nats, kaddr, SUM_JOURNAL_SIZE);

    curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
    memcpy(&curseg->sum_blk->journal.n_sits, kaddr + SUM_JOURNAL_SIZE,
                        SUM_JOURNAL_SIZE);

    offset = 2 * SUM_JOURNAL_SIZE;
    for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
        unsigned short blk_off;
        struct curseg_info *curseg = CURSEG_I(sbi, i);

        reset_curseg(sbi, i);

        blk_off = le16_to_cpu(ckpt->cur_data_blkoff[i]);
        curseg->next_blkoff = blk_off;

        if (curseg->alloc_type == SSR)
            blk_off = sbi->blocks_per_seg;
        else
            blk_off = curseg->next_blkoff;

        /* Restore the meta data From compated ssa area */
        for (j = 0; j < blk_off; j++) {
            struct f2fs_summary *s;
            s = (struct f2fs_summary *)(kaddr + offset);
            curseg->sum_blk->entries[j] = *s;
            offset += SUMMARY_SIZE;
            if (offset + SUMMARY_SIZE <=
                    PAGE_CACHE_SIZE - SUM_FOOTER_SIZE)
                continue;
            memset(kaddr, 0, PAGE_SIZE);
            ret = dev_read_block(kaddr, start++);
            ASSERT(ret >= 0);
            offset = 0;
        }
    }
    free(kaddr);
}

static int build_sit_info(struct f2fs_sb_info *sbi)
{
    struct f2fs_super_block *raw_sb = F2FS_RAW_SUPER(sbi);
    struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
    struct sit_info *sit_i;
    unsigned int sit_segs, start;
    char *src_bitmap, *dst_bitmap;
    unsigned int bitmap_size;
	struct timeval time;

    sit_i = malloc(sizeof(struct sit_info));
	ASSERT(sit_i);

    SM_I(sbi)->sit_info = sit_i;

    sit_i->sentries = calloc(TOTAL_SEGS(sbi) * sizeof(struct seg_entry), 1);
	ASSERT(sit_i->sentries);

    bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));
    sit_i->dirty_sentries_bitmap = calloc(bitmap_size, 1);
	ASSERT(sit_i->dirty_sentries_bitmap);

    for (start = 0; start < TOTAL_SEGS(sbi); start++) {
        sit_i->sentries[start].cur_valid_map
            = calloc(SIT_VBLOCK_MAP_SIZE, 1);
        sit_i->sentries[start].ckpt_valid_map
            = calloc(SIT_VBLOCK_MAP_SIZE, 1);
        if (!sit_i->sentries[start].cur_valid_map
                || !sit_i->sentries[start].ckpt_valid_map)
            return -ENOMEM;
    }

    sit_segs = le32_to_cpu(raw_sb->segment_count_sit) >> 1;
    bitmap_size = __bitmap_size(sbi, SIT_BITMAP);
    src_bitmap = __bitmap_ptr(sbi, SIT_BITMAP);

    dst_bitmap = malloc(bitmap_size);
	ASSERT(dst_bitmap);
    memcpy(dst_bitmap, src_bitmap, bitmap_size);

    sit_i->sit_base_addr = le32_to_cpu(raw_sb->sit_blkaddr);
    sit_i->sit_blocks = sit_segs << sbi->log_blocks_per_seg;
    sit_i->written_valid_blocks = le64_to_cpu(ckpt->valid_block_count);
    sit_i->sit_bitmap = dst_bitmap;
    sit_i->bitmap_size = bitmap_size;
    sit_i->dirty_sentries = 0;
    sit_i->sents_per_block = SIT_ENTRY_PER_BLOCK;

	/* Init time, which is improtant for gc afterwards */
	gettimeofday(&time, (struct timezone *)NULL);
	sit_i->mounted_time = le64_to_cpu(time.tv_sec);
    sit_i->elapsed_time = le64_to_cpu(ckpt->elapsed_time);
	MSG(1, "elapsed_time:%lld\n", sit_i->elapsed_time);
	MSG(1, "mounted_time:%lld\n", sit_i->mounted_time);
    return 0;
}

static void restore_node_summary(struct f2fs_sb_info *sbi,
        unsigned int segno, struct f2fs_summary_block *sum_blk)
{
    struct f2fs_node *node_blk;
    struct f2fs_summary *sum_entry;
    block_t addr;
    unsigned int i;
    int ret;

    node_blk = malloc(F2FS_BLKSIZE);
    ASSERT(node_blk);

    /* scan the node segment */
    addr = START_BLOCK(sbi, segno);
    sum_entry = &sum_blk->entries[0];

    for (i = 0; i < sbi->blocks_per_seg; i++, sum_entry++) {
        ret = dev_read_block(node_blk, addr);
        ASSERT(ret >= 0);
        sum_entry->nid = node_blk->footer.nid;
        addr++;
    }
    free(node_blk);
}

static void read_normal_summaries(struct f2fs_sb_info *sbi, int type)
{
    struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
    struct f2fs_summary_block *sum_blk;
    struct curseg_info *curseg;
    unsigned int segno = 0;
    unsigned short blk_off;
    block_t blk_addr = 0;
    int ret;

    if (IS_DATASEG(type)) {
        segno = le32_to_cpu(ckpt->cur_data_segno[type]);
        blk_off = le16_to_cpu(ckpt->cur_data_blkoff[type - CURSEG_HOT_DATA]);

        if (is_set_ckpt_flags(ckpt, CP_UMOUNT_FLAG))
            blk_addr = sum_blk_addr(sbi, NR_CURSEG_TYPE, type);
        else
            blk_addr = sum_blk_addr(sbi, NR_CURSEG_DATA_TYPE, type);
    } else {
        segno = le32_to_cpu(ckpt->cur_node_segno[type -
                            CURSEG_HOT_NODE]);
        blk_off = le16_to_cpu(ckpt->cur_node_blkoff[type - CURSEG_HOT_NODE]);
        if (is_set_ckpt_flags(ckpt, CP_UMOUNT_FLAG))
            blk_addr = sum_blk_addr(sbi, NR_CURSEG_NODE_TYPE,
                            type - CURSEG_HOT_NODE);
        else
            blk_addr = GET_SUM_BLKADDR(sbi, segno);
    }

    sum_blk = (struct f2fs_summary_block *)malloc(PAGE_SIZE);
	ASSERT(sum_blk);
    ret = dev_read_block(sum_blk, blk_addr);
    ASSERT(ret >= 0);

    if (IS_NODESEG(type) && !is_set_ckpt_flags(ckpt, CP_UMOUNT_FLAG))
        restore_node_summary(sbi, segno, sum_blk);

    curseg = CURSEG_I(sbi, type);
    memcpy(curseg->sum_blk, sum_blk, PAGE_CACHE_SIZE);
    reset_curseg(sbi, type);
    curseg->next_blkoff = blk_off;
    free(sum_blk);
}

static void restore_curseg_summaries(struct f2fs_sb_info *sbi)
{
    int type = CURSEG_HOT_DATA;

    if (is_set_ckpt_flags(F2FS_CKPT(sbi), CP_COMPACT_SUM_FLAG)) {
        read_compacted_summaries(sbi);
        type = CURSEG_HOT_NODE;
    }

    for (; type <= CURSEG_COLD_NODE; type++)
        read_normal_summaries(sbi, type);

}
static void build_curseg(struct f2fs_sb_info *sbi)
{
    struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
    struct curseg_info *array;
    unsigned short blk_off;
    unsigned int segno;
    int i;

    array = malloc(sizeof(*array) * NR_CURSEG_TYPE);
	ASSERT(array);

    SM_I(sbi)->curseg_array = array;

    for (i = 0; i < NR_CURSEG_TYPE; i++) {
        array[i].sum_blk = malloc(PAGE_CACHE_SIZE);
		ASSERT(array[i].sum_blk);
        if (i <= CURSEG_COLD_DATA) {
            blk_off = le16_to_cpu(ckpt->cur_data_blkoff[i]);
            segno = le32_to_cpu(ckpt->cur_data_segno[i]);
        }
        if (i > CURSEG_COLD_DATA) {
            blk_off = le16_to_cpu(ckpt->cur_node_blkoff[i -
                            CURSEG_HOT_NODE]);
            segno = le32_to_cpu(ckpt->cur_node_segno[i -
                            CURSEG_HOT_NODE]);
        }
        array[i].segno = segno;
        array[i].zone = GET_ZONENO_FROM_SEGNO(sbi, segno);
        array[i].next_segno = segno;
        array[i].next_blkoff = blk_off;
        array[i].alloc_type = ckpt->alloc_type[i];
    }
    restore_curseg_summaries(sbi);
}

static void build_sit_entries(struct f2fs_sb_info *sbi)
{
    struct sit_info *sit_i = SIT_I(sbi);
    struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
    struct f2fs_journal *journal = &curseg->sum_blk->journal;
    unsigned int segno;

    for (segno = 0; segno < TOTAL_SEGS(sbi); segno++) {
        struct seg_entry *se = &sit_i->sentries[segno];
        struct f2fs_sit_block *sit_blk;
        struct f2fs_sit_entry sit;
        int i;

        for (i = 0; i < sits_in_cursum(journal); i++) {
            if (le32_to_cpu(segno_in_journal(journal, i)) == segno) {
                sit = sit_in_journal(journal, i);
                goto got_it;
            }
        }
        sit_blk = get_current_sit_page(sbi, segno);
        sit = sit_blk->entries[SIT_ENTRY_OFFSET(sit_i, segno)];
        free(sit_blk);
got_it:
        check_block_count(sbi, segno, &sit);
        seg_info_from_raw_sit(se, &sit);
    }

}

int build_segment_manager(struct f2fs_sb_info *sbi)
{
    struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
    struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
    struct f2fs_sm_info *sm_info;
	int err = -1;

    sm_info = malloc(sizeof(struct f2fs_sm_info));
    if (!sm_info)
        return -ENOMEM;

    /* init sm info */
    sbi->sm_info = sm_info;
    sm_info->seg0_blkaddr = le32_to_cpu(raw_super->segment0_blkaddr);
    sm_info->main_blkaddr = le32_to_cpu(raw_super->main_blkaddr);
    sm_info->segment_count = le32_to_cpu(raw_super->segment_count);
    sm_info->sloadd_segments = le32_to_cpu(ckpt->rsvd_segment_count);
    sm_info->ovp_segments = le32_to_cpu(ckpt->overprov_segment_count);
    sm_info->main_segments = le32_to_cpu(raw_super->segment_count_main);
    sm_info->ssa_blkaddr = le32_to_cpu(raw_super->ssa_blkaddr);

    /* Init the flip_bitmap to record which sit block need flip */
    unsigned int flip_bitmap_size;
    flip_bitmap_size = (le32_to_cpu(raw_super->segment_count_sit) >> 1)
            << le32_to_cpu(raw_super->log_blocks_per_seg);
    sm_info->flip_bitmap = malloc(flip_bitmap_size);
	ASSERT(sm_info->flip_bitmap);
    sm_info->flip_bitmap_size = flip_bitmap_size;
    memset(sm_info->flip_bitmap, 0x00, flip_bitmap_size);

    build_sit_info(sbi);

    /* Necessary! alloc free_segmap & free_secmap for segment allocation */
    err = build_free_segmap(sbi);

    build_curseg(sbi);

    build_sit_entries(sbi);

    /* Necessary! init free_segmap & free_secmap */
    init_free_segmap(sbi);

    return err;
}

void write_normal_summaries(struct f2fs_sb_info *sbi,
                    block_t blkaddr, int type)
{
    int i, end;
    if (IS_DATASEG(type))
        end = type + NR_CURSEG_DATA_TYPE;
    else
        end = type + NR_CURSEG_NODE_TYPE;

    for (i = type; i < end; i++) {
        struct curseg_info *sum = CURSEG_I(sbi, i);
        dev_write(sum->sum_blk, (blkaddr +
				(i - type)) * F2FS_BLKSIZE, F2FS_BLKSIZE);
    }
}

static void flip_sit_bitmap(struct f2fs_sb_info *sbi)
{
    struct f2fs_sm_info *sm_info = SM_I(sbi);

    unsigned long bit_start = 0, bit_pos;

next:
    bit_pos = find_next_bit_le_sload((char *)sm_info->flip_bitmap,
					sm_info->flip_bitmap_size, bit_start);

    if (bit_pos >= sm_info->flip_bitmap_size)
        goto out;

    change_bit(bit_pos , sm_info->sit_info->sit_bitmap);
    bit_start = bit_pos + 1;
    goto next;
out:
    return;
}

void flush_sit_entries(struct f2fs_sb_info *sbi)
{
    struct f2fs_sm_info *sm_info = SM_I(sbi);
    struct sit_info *sit_i = SIT_I(sbi);
    int bit_start = 0, bit_pos;
next:
    bit_pos = find_next_bit_le_sload((char *)sit_i->dirty_sentries_bitmap,
                    sm_info->main_segments, bit_start);

    if (bit_pos >= sm_info->main_segments)
        goto out;
    update_sit(sbi, bit_pos);

    bit_start = bit_pos + 1;
    goto next;
out:
    flip_sit_bitmap(sbi);
    return ;

}
