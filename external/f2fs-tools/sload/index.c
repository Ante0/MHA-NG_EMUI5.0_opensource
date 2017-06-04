#include <f2fs_fs.h>
#include "sload.h"

#include "node.h"
#include "f2fs.h"
#include <stdio.h>

#include "index.h"
#include "bit_operations.h"

/*
 * get_node_path - Get the index path of pgoff_t block
 * @offset: offset in the current index node block.
 * @noffset: NO. of the index block within a file.
 * return: depth of the index path.
 *
 * TODO: No INLINE considering.
 */
static int get_node_path(unsigned long block,
				int offset[4], unsigned int noffset[4])
{
	const long direct_index = DEF_ADDRS_PER_INODE;
	const long direct_blks = ADDRS_PER_BLOCK;
	const long dptrs_per_blk = NIDS_PER_BLOCK;
	const long indirect_blks = ADDRS_PER_BLOCK * NIDS_PER_BLOCK;
	const long dindirect_blks = indirect_blks * NIDS_PER_BLOCK;

	int n = 0;
	int level = 0;

	noffset[0] = 0;
	if (block < direct_index) {
		offset[n] = block;
		goto got;
	}

	block -= direct_index;
	if (block < direct_blks) {
		offset[n++] = NODE_DIR1_BLOCK;
		noffset[n]= 1;
		offset[n] = block;
		level = 1;
		goto got;
	}
	block -= direct_blks;
	if (block < direct_blks) {
		offset[n++] = NODE_DIR2_BLOCK;
		noffset[n] = 2;
		offset[n] = block;
		level = 1;
		goto got;
	}
    block -= direct_blks;
    if (block < indirect_blks) {
        offset[n++] = NODE_IND1_BLOCK;
        noffset[n] = 3;
        offset[n++] = block / direct_blks;
        noffset[n] = 4 + offset[n - 1];
        offset[n] = block % direct_blks;
        level = 2;
        goto got;
    }
    block -= indirect_blks;
    if (block < indirect_blks) {
        offset[n++] = NODE_IND2_BLOCK;
        noffset[n] = 4 + dptrs_per_blk;
        offset[n++] = block / direct_blks;
        noffset[n] = 5 + dptrs_per_blk + offset[n - 1];
        offset[n] = block % direct_blks;
        level = 2;
        goto got;
    }
    block -= indirect_blks;
    if (block < dindirect_blks) {
        offset[n++] = NODE_DIND_BLOCK;
        noffset[n] = 5 + (dptrs_per_blk * 2);
        offset[n++] = block / indirect_blks;
        noffset[n] = 6 + (dptrs_per_blk * 2) +
                  offset[n - 1] * (dptrs_per_blk + 1);
        offset[n++] = (block / direct_blks) % dptrs_per_blk;
        noffset[n] = 7 + (dptrs_per_blk * 2) +
                  offset[n - 2] * (dptrs_per_blk + 1) +
                  offset[n - 1];
        offset[n] = block % direct_blks;
        level = 3;
        goto got;
    } else {
		ERR_MSG("Invalid index");
    }
got:
    return level;
}

/* This function is the core function to build the index of a file(directory).
 * Most of the file are copied from Kernel.
 * The original part of the file is related to struct page.
 * Pay more attention to this function, it may lead to memory leak.
 */
int get_dnode_of_data(struct f2fs_sb_info *sbi, struct dnode_of_data *dn,
				unsigned long i_ino, pgoff_t index, int mode)
{
	int offset[4];
	unsigned int noffset[4];
	struct f2fs_node *parent = NULL;
	nid_t nids[4];
	block_t nblk[4];
	struct node_info ni;
	int level, i;
	int err = 0, ret;

	level = get_node_path(index, offset, noffset);

	ASSERT(!dn->node_page);

	nids[0] = i_ino;
	parent = dn->inode_page;
	if (level != 0)
		nids[1] = get_nid(parent, offset[0], true);
	else
		dn->node_page = dn->inode_page;

	get_node_info(sbi, i_ino, &ni);
	nblk[0] = ni.blk_addr; /* */

	for (i = 1; i <= level; i++) {
		if (!nids[i] && mode == ALLOC_NODE) {
			f2fs_alloc_nid(sbi, &nids[i], 1);
			if (!nids[i]) {
				err = -ENOSPC;
				goto release_pages;
			}
			dn->nid = nids[i];

			/* Function new_node_page get a new f2fs_node page and update*/
			/* We should make sure that dn->node_page == NULL*/
			nblk[i] = new_node_page(sbi, dn, noffset[i]);

			ASSERT(nblk[i]);
			set_nid(parent, offset[i - 1], nids[i], i == 1);

		} else {
			/* If Sparse file no read API, */
			struct node_info ni;
			get_node_info(sbi, nids[i], &ni);

			/* Check if ni.blkaddr is NULL*/
			if (ni.blk_addr == NULL) {
				if (i != 1)
					free(parent);
				dn->data_blkaddr = NULL_ADDR;
				goto release_pages;
			}
			dn->node_page = calloc(BLOCK_SZ, 1);
			ASSERT(dn->node_page);
			ret = dev_read_block(dn->node_page, ni.blk_addr);
			if (ret < 0) {
				ERR_MSG("\tError: Fail to Read block\n");
				return -1;
			}

			nblk[i] = ni.blk_addr;
		}

		if (mode == ALLOC_NODE){ /* Parent node may have changed */
			ret = dev_write_block(parent, nblk[i-1]);
		    if (ret < 0) {
				ERR_MSG("\tError: Fail to Write block\n");
				return -1;
			}
		}
		if (i != 1)
			free(parent);

		if (i < level) {
			parent = dn->node_page;
			nids[i + 1] = get_nid(parent, offset[i], false);
		}
	}

	dn->nid = nids[level];
	dn->ofs_in_node = offset[level];
	dn->data_blkaddr = datablock_addr(dn->node_page, dn->ofs_in_node);
	dn->node_blkaddr = nblk[level];
	return err;
release_pages:
	dn->node_page = NULL;
	return err;
}

void set_data_blkaddr(struct dnode_of_data *dn)
{
    __le32 *addr_array;
    struct f2fs_node *node_page = dn->node_page;
    unsigned int ofs_in_node = dn->ofs_in_node;

    addr_array = blkaddr_in_node(node_page);
    addr_array[ofs_in_node] = cpu_to_le32(dn->data_blkaddr);
}

void set_new_dnode(struct dnode_of_data *dn,
				struct f2fs_node *ipage, struct f2fs_node *npage, nid_t nid)
{
	memset(dn, 0, sizeof(*dn));
	dn->inode_page = ipage;
	dn->node_page = npage;
	dn->nid = nid;
}
