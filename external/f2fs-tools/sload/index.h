#ifndef _INDEX_H_
#define _INDEX_H_
int get_dnode_of_data(struct f2fs_sb_info *sbi, struct dnode_of_data *dn,
			unsigned long i_ino, pgoff_t index, int mode);
void set_data_blkaddr(struct dnode_of_data *dn);
void set_new_dnode(struct dnode_of_data *dn,
				struct f2fs_node *ipage, struct f2fs_node *npage, nid_t nid);
#endif
