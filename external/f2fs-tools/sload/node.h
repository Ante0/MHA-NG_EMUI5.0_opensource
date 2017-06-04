#ifndef _NODE_H_
#define _NODE_H_
#include <f2fs_fs.h>        
#include "sload.h"
#include "f2fs.h"

#define NAT_BLOCK_OFFSET(start_nid) (start_nid / NAT_ENTRY_PER_BLOCK)
static inline void set_nid(struct f2fs_node * rn, int off, nid_t nid, bool i)
{
	if (i)
		rn->i.i_nid[off - NODE_DIR1_BLOCK] = cpu_to_le32(nid);
	else
		rn->in.nid[off] = cpu_to_le32(nid);
}

static inline nid_t get_nid(struct f2fs_node * rn, int off, bool i)
{
	if (i)
		return le32_to_cpu(rn->i.i_nid[off - NODE_DIR1_BLOCK]);
	else
		return le32_to_cpu(rn->in.nid[off]);
}

struct node_info {
    nid_t nid; /*node id*/
    nid_t ino; /*inode number of the node's owner*/
    block_t blk_addr; /* block address of the node */
    unsigned char version; /* version of the node */
    unsigned char flag; /* for node information bits */
};

#define RAW_IS_INODE(p) ((p)->footer.nid == (p)->footer.ino)

static int IS_INODE(struct f2fs_node *node)
{
	ASSERT(node);
	return ((node)->footer.nid == (node)->footer.ino);
}

#define ADDRS_PER_PAGE(page) \
		(IS_INODE(page) ? DEF_ADDRS_PER_INODE : ADDRS_PER_BLOCK)

static inline unsigned int ofs_of_node(struct f2fs_node *node_blk)
{
    unsigned flag = le32_to_cpu(node_blk->footer.flag);
    return flag >> OFFSET_BIT_SHIFT;
}

static inline bool IS_DNODE(struct f2fs_node *node_page)
{
	unsigned int ofs = ofs_of_node(node_page);

	if (f2fs_has_xattr_block(ofs))
		return false;

	if (ofs == 3 || ofs == 4 + NIDS_PER_BLOCK ||
			ofs == 5 + 2 * NIDS_PER_BLOCK)
		return false;

	if (ofs >= 6 + 2 * NIDS_PER_BLOCK) {
		ofs -= 6 + 2 * NIDS_PER_BLOCK;
		if (!((long int)ofs % (NIDS_PER_BLOCK + 1)))
				return false;
	}
	return true;
}
static __le32 *blkaddr_in_node(struct f2fs_node *node)
{
    return IS_INODE(node) ? node->i.i_addr : node->dn.addr;
}

static inline block_t datablock_addr(struct f2fs_node *node_page,
				unsigned int offset)
{
	__le32 *addr_array;

	ASSERT(node_page);
	addr_array = blkaddr_in_node(node_page);
	return le32_to_cpu(addr_array[offset]);
}

static inline void fill_node_footer_blkaddr(struct f2fs_node *node, block_t blkaddr)
{
	node->footer.next_blkaddr = cpu_to_le32(blkaddr);
}

static inline void node_info_from_raw_nat(struct node_info *ni,
        struct f2fs_nat_entry *raw_nat)
{
    ni->ino = le32_to_cpu(raw_nat->ino);
    ni->blk_addr = le32_to_cpu(raw_nat->block_addr);
    ni->version = raw_nat->version;
}

static inline void get_nat_bitmap(struct f2fs_sb_info *sbi, void *addr)
{
    struct f2fs_nm_info *nm_i = NM_I(sbi);
    memcpy(addr, nm_i->nat_bitmap, nm_i->bitmap_size);
}

inline void get_nat_bitmap(struct f2fs_sb_info *sbi, void *addr);
int update_nat(struct f2fs_sb_info *sbi, nid_t nid, nid_t ino, block_t blk);
block_t new_node_page(struct f2fs_sb_info *sbi,
				struct dnode_of_data *dn, unsigned int ofs);
int build_node_manager(struct f2fs_sb_info *sbi);
void remove_nats_in_journal(struct f2fs_sb_info *sbi);
void get_node_info(struct f2fs_sb_info *sbi, nid_t nid, struct node_info *ni);
bool f2fs_alloc_nid(struct f2fs_sb_info *sbi, nid_t *nid, bool alloc);
void f2fs_free_nid_bitmap(struct f2fs_sb_info *sbi);
void flip_nat_bitmap(struct f2fs_sb_info *sbi);

#endif /* _NODE_H_ */
