#include <f2fs_fs.h>
#include "sload.h"
#include "node.h"
#include "f2fs.h"
#include "segment.h"
#include "index.h"
#include "bit_operations.h"

int f2fs_write(struct f2fs_sb_info *sbi, nid_t ino, void * buffer,
				u64 count, pgoff_t offset)
{
	u64 start = F2FS_BYTES_TO_BLK(offset);
	u64 len = F2FS_BYTES_TO_BLK(count);
	u64 end_offset;
	u64 off_in_block, len_in_block, len_already;
	struct dnode_of_data dn = {0};
	void *data_page;
	struct node_info ni;
	struct f2fs_node *inode;
	int ret = -1;

	get_node_info(sbi, ino, &ni);
	inode = calloc(BLOCK_SZ, 1);
	if (inode == NULL) {
		MSG(0, "\tError: Calloc Failed for inode!\n");
		return -1;
	}
	ret = dev_read_block(inode, ni.blk_addr);
	if (ret < 0) {
		ERR_MSG("\tError: Fail to Read Block\n");
		goto free_inode;
	}

	if (S_ISDIR(inode->i.i_mode) || S_ISLNK(inode->i.i_mode)) {
		ERR_MSG("\tFault Write to A Dir or Lnk \n");
		ret = -1;
		goto free_inode;
	}
	off_in_block = offset & ((1 << F2FS_BLKSIZE_BITS) - 1);
	len_in_block = (1 << F2FS_BLKSIZE_BITS) - off_in_block;
	len_already = 0;

	/* When calculate how many blocks this 'count' stride accross,
	 * We should take offset in a block in account.
	 */
	len = F2FS_BYTES_TO_BLK(count + off_in_block
					+ ((1 << F2FS_BLKSIZE_BITS) -1));

	data_page = calloc(BLOCK_SZ, 1);
	if (data_page == NULL) {
		ERR_MSG("\tError: Calloc Failed for inode!\n");
		ret = -1;
		goto free_inode;
	}

	while (len) {
		if (dn.node_page && dn.node_page != dn.inode_page)
			free(dn.node_page);
		set_new_dnode(&dn, inode, NULL, inode->footer.ino);
		get_dnode_of_data(sbi, &dn, inode->footer.ino,
						start, ALLOC_NODE);

		end_offset = ADDRS_PER_PAGE(dn.node_page);

		while (dn.ofs_in_node < end_offset && len) {
			block_t blkaddr;

			blkaddr = datablock_addr(dn.node_page, dn.ofs_in_node);
			if (blkaddr == NULL_ADDR) { /* A new page from WARM_DATA */
				blkaddr = allocate_data_block(sbi, &dn, NULL, CURSEG_WARM_DATA);
				dn.data_blkaddr = blkaddr;
				set_data_blkaddr(&dn);

				/* Direct node should be update */
				ret = dev_write_block(dn.node_page, dn.node_blkaddr);
				if (ret < 0) {
					ERR_MSG("\tError: Fail to Write block\n");
					goto free_node_page;
				}
			}

			/* Copy data from buffer to file */
			ret = dev_read_block(data_page, blkaddr);
			if (ret < 0) {
				ERR_MSG("\tError: Fail to Read block\n");
				goto free_node_page;
			}

			memcpy(data_page + off_in_block, buffer, len_in_block);

			ret = dev_write_block(data_page, blkaddr);
			if (ret < 0) {
				ERR_MSG("\tError: Fail to Write block\n");
				goto free_node_page;
			}

			off_in_block = 0;
			len_already += len_in_block;
			len_in_block = ((count - len_already) > (1 << F2FS_BLKSIZE_BITS)) ?
					(1 << F2FS_BLKSIZE_BITS) :
					(count - len_already);
			len--;
			start++;
			dn.ofs_in_node++;
		}
		/* Update the direct node */
		struct node_info ni;
		get_node_info(sbi, dn.node_page->footer.nid, &ni);
		ret = dev_write_block(dn.node_page, ni.blk_addr);
		if (ret < 0) {
			ERR_MSG("\tError: Fail to Write block\n");
			goto free_node_page;
		}

	}

	/* Update the inode info */
	if (inode->i.i_size < offset + count) {
		inode->i.i_size = offset + count;
	}

	ret = dev_write_block(inode, ni.blk_addr);
	if (ret < 0) {
		ERR_MSG("\tError: Fail to Write block\n");
		goto free_node_page;
	}

free_node_page:
	if (dn.node_page && dn.node_page != dn.inode_page)
		free(dn.node_page);
	free(data_page);
free_inode:
	free(inode);

	return ret;
}
