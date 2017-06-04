#include <f2fs_fs.h>
#include "sload.h"
#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "bit_operations.h"

static pgoff_t current_nat_addr(struct f2fs_sb_info *sbi, nid_t start)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	pgoff_t block_off;
	pgoff_t block_addr;
	int seg_off;

	block_off = NAT_BLOCK_OFFSET(start);
	seg_off = block_off >> sbi->log_blocks_per_seg;

	block_addr = (pgoff_t)(nm_i->nat_blkaddr +
			(seg_off << sbi->log_blocks_per_seg << 1) +
			(block_off & ((1 << sbi->log_blocks_per_seg) -1)));

	if (f2fs_test_bit(block_off, nm_i->nat_bitmap))
		block_addr += sbi->blocks_per_seg;

	return block_addr;
}

static pgoff_t next_nat_addr(struct f2fs_sb_info *sbi,
				pgoff_t block_addr)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	block_addr -= nm_i->nat_blkaddr;
	if ((block_addr >> sbi->log_blocks_per_seg) % 2)
		block_addr -= sbi->blocks_per_seg;
	else
		block_addr += sbi->blocks_per_seg;

	return block_addr + nm_i->nat_blkaddr;
}

int update_nat(struct f2fs_sb_info *sbi, nid_t nid, nid_t ino, block_t blk)
{
	struct f2fs_nat_block *nat_block;
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct f2fs_nat_entry *nat_entry;
	unsigned int block_off = NAT_BLOCK_OFFSET(nid);
	block_t block_offset, curr_addr, next_addr;
	int off_in_nat_block;
	int ret = -1;

	block_offset = NAT_BLOCK_OFFSET(nid);
	curr_addr = current_nat_addr(sbi, nid);
	next_addr = next_nat_addr(sbi, curr_addr);

	nat_block = calloc(BLOCK_SZ, 1);
	if (nat_block == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		return -1;
	}

	/* If this is the first time we should use current NAT area. */
	if (f2fs_test_bit(block_off, nm_i->nat_flip_bitmap)) {
		ret = dev_read_block(nat_block, next_addr);
	}
	else {
		ret = dev_read_block(nat_block, curr_addr);
	}
	if (ret < 0) {
		ERR_MSG("\tError: Fail to Read block\n");
		goto free_nat_block;
	}

	off_in_nat_block = nid % NAT_ENTRY_PER_BLOCK;
	nat_entry = &(nat_block->entries[off_in_nat_block]);

	/* Only when node is removed, node nat_entry.version needs updating */
	nat_entry->ino = ino;
	nat_entry->block_addr = blk;

	ret = dev_write_block(nat_block, next_addr);
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Write block\n");
        goto free_nat_block;
    }

	/* Update the flip_bitmap */
	f2fs_set_bit(block_offset, nm_i->nat_flip_bitmap);
	MSG(2, "Update the %d NAT blocks\n", block_off);
free_nat_block:
	free(nat_block);
	return ret;

}

static int lookup_nat_in_journal(struct f2fs_sb_info *sbi, u32 nid,
                    struct f2fs_nat_entry *raw_nat)
{
    struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
    struct f2fs_journal *journal = &curseg->sum_blk->journal;
    int i = 0;

    for (i = 0; i < nats_in_cursum(journal); i++) {
        if (le32_to_cpu(nid_in_journal(journal, i)) == nid) {
            memcpy(raw_nat, &nat_in_journal(journal, i),
                        sizeof(struct f2fs_nat_entry));
            DBG(3, "==> Found nid [0x%x] in nat cache\n", nid);
            return i;
        }
    }
    return -1;
}

static int get_nat_entry(struct f2fs_sb_info *sbi, nid_t nid,
                struct f2fs_nat_entry *raw_nat)
{
    struct f2fs_nm_info *nm_i = NM_I(sbi);
    struct f2fs_nat_block *nat_block;
    pgoff_t block_off;
    pgoff_t block_addr;
    int seg_off, entry_off;
    int ret;

    if (lookup_nat_in_journal(sbi, nid, raw_nat) >= 0)
        return -1;

    nat_block = (struct f2fs_nat_block *)calloc(BLOCK_SZ, 1);
	if (nat_block == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		return -1;
	}

    block_off = nid / NAT_ENTRY_PER_BLOCK;
    entry_off = nid % NAT_ENTRY_PER_BLOCK;

    seg_off = block_off >> sbi->log_blocks_per_seg;
    block_addr = (pgoff_t)(nm_i->nat_blkaddr +
            (seg_off << sbi->log_blocks_per_seg << 1) +
            (block_off & ((1 << sbi->log_blocks_per_seg) - 1)));

    if (f2fs_test_bit(block_off, nm_i->nat_bitmap))
        block_addr += sbi->blocks_per_seg;

    /* If the NAT block is already dirty, we should read it from 'next' area */
    if (f2fs_test_bit(block_off, nm_i->nat_flip_bitmap))
        block_addr = next_nat_addr(sbi, block_addr);


    ret = dev_read_block(nat_block, block_addr);
	if (ret < 0) {
		ERR_MSG("\tError: Fail to Read block\n");
		goto free_nat_block;
	}
    memcpy(raw_nat, &nat_block->entries[entry_off],
                    sizeof(struct f2fs_nat_entry));
free_nat_block:
    free(nat_block);
	return ret;
}


/* Because we have store Node Info into the 'Next' Area, so
   we should get_node_info from Next Area*/
void get_node_info(struct f2fs_sb_info *sbi, nid_t nid, struct node_info *ni)
{
    struct f2fs_nat_entry raw_nat = {0};
    get_nat_entry(sbi, nid, &raw_nat);
    ni->nid = nid;
    node_info_from_raw_nat(ni, &raw_nat);
}

/*
 * In this function, we get a new node page, and write back
 * node_page would be sloadd in RAM, linked by dn->node_page
 */
block_t new_node_page(struct f2fs_sb_info *sbi,
				struct dnode_of_data *dn, unsigned int ofs)
{
	struct f2fs_node *f2fs_inode;
	struct f2fs_node *node_page;
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	block_t addr;
	int ret;

	f2fs_inode = dn->inode_page;
	// write node page
	node_page = calloc(BLOCK_SZ, 1);
	if (node_page == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		return -1;
	}

	node_page->footer.nid = dn->nid;
	node_page->footer.ino = f2fs_inode->footer.ino;
	node_page->footer.flag = cpu_to_le32(ofs << OFFSET_BIT_SHIFT);
	node_page->footer.cp_ver = le64_to_cpu(ckpt->checkpoint_ver);

	if (IS_DNODE(node_page) && S_ISDIR(f2fs_inode->i.i_mode)) {
		addr = allocate_data_block(sbi, dn, node_page, CURSEG_HOT_NODE);
	} else if(IS_DNODE(node_page) && S_ISREG(f2fs_inode->i.i_mode)) {
		addr = allocate_data_block(sbi, dn, node_page, CURSEG_WARM_NODE);
	} else
	 	addr = allocate_data_block(sbi, dn, node_page, CURSEG_COLD_NODE);

	/* update nat info */
	update_nat(sbi, dn->nid, f2fs_inode->footer.ino, addr);

	ret = dev_write_block(node_page, addr);
    if (ret < 0) {
        ERR_MSG("\tError: Fail to Write block\n");
		return -1;
    }
	dn->node_page = node_page;
	return addr;
}

void remove_nats_in_journal(struct f2fs_sb_info *sbi)
{
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
	struct f2fs_journal *journal = &curseg->sum_blk->journal;
	int i;

	for (i = 0; i < nats_in_cursum(journal); i++) {
		nid_t nid;
		struct f2fs_nat_entry raw_ne;

		nid = le32_to_cpu(nid_in_journal(journal, i));
		raw_ne = nat_in_journal(journal, i);

		update_nat(sbi, nid, raw_ne.ino, raw_ne.block_addr);
	}

	journal->n_nats = 0;
}

bool f2fs_alloc_nid(struct f2fs_sb_info *sbi, nid_t *nid, bool alloc)
{
    struct f2fs_nm_info *nm_i = NM_I(sbi);
    nid_t i;

    for (i = 0; i < nm_i->max_nid; i++) {
        if(f2fs_test_bit(i, nm_i->nid_bitmap) == 0)
            break;
    }
    if (i >= nm_i->max_nid) {
        return 0;
    }

    if (alloc) {
        f2fs_set_bit(i, nm_i->nid_bitmap);
    }

    *nid = i;

    return 1;
}

static int f2fs_init_nid_bitmap(struct f2fs_sb_info *sbi)
{
    struct f2fs_nm_info *nm_i = NM_I(sbi);
    int nid_bitmap_size = (nm_i->max_nid + BITS_PER_BYTE - 1) / BITS_PER_BYTE;
    struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
    struct f2fs_journal *journal = &curseg->sum_blk->journal;
    struct f2fs_nat_block nat_block;
    block_t start_blk;
    nid_t nid;
    int i;

    nm_i->nid_bitmap = (char *)calloc(nid_bitmap_size, 1);
	if (nm_i->nid_bitmap == NULL) {
		ERR_MSG("\tError: Calloc Failed!\n");
		return -1;
	}
    nm_i->nid_bitmap_size = nid_bitmap_size;

    // arbitrarily set 0 bit
    f2fs_set_bit(0, nm_i->nid_bitmap);

    memset((void *)&nat_block, 0, sizeof(struct f2fs_nat_block));

    for(nid = 0; nid < nm_i->max_nid; nid++) {
        if(!(nid % NAT_ENTRY_PER_BLOCK)) {
            start_blk = current_nat_addr(sbi, nid);
            dev_read((void *)&nat_block, start_blk * F2FS_BLKSIZE, F2FS_BLKSIZE);
        }

        if(le32_to_cpu(nat_block.entries[nid % NAT_ENTRY_PER_BLOCK].block_addr)
				 != NULL_ADDR) {
            f2fs_set_bit(nid, nm_i->nid_bitmap);
        }
    }

    for (i = 0; i < nats_in_cursum(journal); i++) {
        block_t addr = le32_to_cpu(nat_in_journal(journal, i).block_addr);
        nid = le32_to_cpu(nid_in_journal(journal, i));
        if (addr != NULL_ADDR) {
            f2fs_set_bit(nid, nm_i->nid_bitmap);
        }
    }

	return 0;
}

void f2fs_free_nid_bitmap(struct f2fs_sb_info *sbi)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	nm_i->nid_bitmap_size = 0;
	free(nm_i->nid_bitmap);
}

static int init_node_manager(struct f2fs_sb_info *sbi)
{
    struct f2fs_super_block *sb_raw = F2FS_RAW_SUPER(sbi);
    struct f2fs_nm_info *nm_i = NM_I(sbi);
    unsigned char *version_bitmap;
    unsigned int nat_segs, nat_blocks;

    nm_i->nat_blkaddr = le32_to_cpu(sb_raw->nat_blkaddr);

    /* segment_count_nat includes pair segment so divide to 2. */
    nat_segs = le32_to_cpu(sb_raw->segment_count_nat) >> 1;
    nat_blocks = nat_segs << le32_to_cpu(sb_raw->log_blocks_per_seg);
    nm_i->max_nid = NAT_ENTRY_PER_BLOCK * nat_blocks;
    nm_i->fcnt = 0;
    nm_i->nat_cnt = 0;
    nm_i->init_scan_nid = le32_to_cpu(sbi->ckpt->next_free_nid);
    nm_i->next_scan_nid = le32_to_cpu(sbi->ckpt->next_free_nid);

    nm_i->bitmap_size = __bitmap_size(sbi, NAT_BITMAP);

    nm_i->nat_bitmap = malloc(nm_i->bitmap_size);
    if (!nm_i->nat_bitmap)
        return -ENOMEM;
    version_bitmap = __bitmap_ptr(sbi, NAT_BITMAP);
    if (!version_bitmap)
        return -EFAULT;

    nm_i->nat_flip_bitmap_size = (le32_to_cpu(sb_raw->segment_count_nat) >> 1)
            << le32_to_cpu(sb_raw->log_blocks_per_seg);
    nm_i->nat_flip_bitmap = malloc(nm_i->nat_flip_bitmap_size);
    if (!nm_i->nat_flip_bitmap)
        return -ENOMEM;
    memset(nm_i->nat_flip_bitmap, 0x00, nm_i->nat_flip_bitmap_size);

    /* copy version bitmap */
    memcpy(nm_i->nat_bitmap, version_bitmap, nm_i->bitmap_size);
    f2fs_init_nid_bitmap(sbi);
    return 0;
}

int build_node_manager(struct f2fs_sb_info *sbi)
{
    int err;
    sbi->nm_info = malloc(sizeof(struct f2fs_nm_info));
    if (!sbi->nm_info)
        return -ENOMEM;

    err = init_node_manager(sbi);
    if (err)
        return err;

    return 0;
}

void flip_nat_bitmap(struct f2fs_sb_info *sbi)
{
    struct f2fs_nm_info *nm_i = NM_I(sbi);
   	unsigned long bit_start = 0, bit_pos;
next:
    bit_pos = find_next_bit_le_sload((char *)nm_i->nat_flip_bitmap,
					nm_i->nat_flip_bitmap_size, bit_start);

    if (bit_pos >= nm_i->nat_flip_bitmap_size)
        goto out;

    change_bit(bit_pos, nm_i->nat_bitmap);
    bit_start = bit_pos + 1;
    goto next;
out:
    return;

}

