typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct btrfs_ioctl_space_info {
	unsigned long long flags;
	unsigned long long total_bytes;
	unsigned long long used_bytes;
};

struct btrfs_ioctl_space_args {
	unsigned long long space_slots;
	unsigned long long total_spaces;
	struct btrfs_ioctl_space_info spaces[0];
};

#define BTRFS_IOCTL_MAGIC 0x94
#define BTRFS_IOC_SUBVOL_GETFLAGS _IOR(BTRFS_IOCTL_MAGIC, 25, unsigned long long)
#define BTRFS_IOC_SPACE_INFO _IOWR(BTRFS_IOCTL_MAGIC, 20, \
                                    struct btrfs_ioctl_space_args)

#define BTRFS_FSID_SIZE 16
struct btrfs_ioctl_fs_info_args {
	unsigned long long max_id;
	unsigned long long num_devices;
	char fsid[BTRFS_FSID_SIZE];
	unsigned long long reserved[124];
};

#define BTRFS_IOC_FS_INFO _IOR(BTRFS_IOCTL_MAGIC, 31, \
		struct btrfs_ioctl_fs_info_args)


#define BTRFS_SUBVOL_NAME_MAX 4039
#define BTRFS_PATH_NAME_MAX 4087

struct btrfs_ioctl_vol_args {
	signed long long fd;
	char name[BTRFS_PATH_NAME_MAX + 1];
};

#define BTRFS_IOCTL_MAGIC 0x94
#define BTRFS_IOC_SUBVOL_CREATE_V2 _IOW(BTRFS_IOCTL_MAGIC, 24, \
                                   struct btrfs_ioctl_vol_args_v2)
#define BTRFS_IOC_SNAP_CREATE_V2 _IOW(BTRFS_IOCTL_MAGIC, 23, \
                                   struct btrfs_ioctl_vol_args_v2)
#define BTRFS_IOC_SUBVOL_CREATE _IOW(BTRFS_IOCTL_MAGIC, 14, \
                                   struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_SNAP_DESTROY _IOW(BTRFS_IOCTL_MAGIC, 15, \
                                   struct btrfs_ioctl_vol_args)

#define BTRFS_QGROUP_INHERIT_SET_LIMITS (1ULL << 0)

struct btrfs_ioctl_vol_args_v2 {
	signed long long fd;
	unsigned long long transid;
	unsigned long long flags;
	union {
		struct {
			unsigned long long size;
			//struct btrfs_qgroup_inherit *qgroup_inherit;
			void *qgroup_inherit;
		};
		unsigned long long unused[4];
	};
	char name[BTRFS_SUBVOL_NAME_MAX + 1];
};

#define BTRFS_ROOT_BACKREF_KEY  144
#define BTRFS_ROOT_TREE_DIR_OBJECTID 6ULL
#define BTRFS_DIR_ITEM_KEY      84

/*
 *  * this is used for both forward and backward root refs
 *   */
struct btrfs_root_ref {
	__le64 dirid;
	__le64 sequence;
	__le16 name_len;
} __attribute__ ((__packed__));

struct btrfs_disk_key {
	__le64 objectid;
	u8 type;
	__le64 offset;
} __attribute__ ((__packed__));

struct btrfs_dir_item {
	struct btrfs_disk_key location;
	__le64 transid;
	__le16 data_len;
	__le16 name_len;
	u8 type;
} __attribute__ ((__packed__));

#define BTRFS_IOCTL_MAGIC 0x94
#define BTRFS_VOL_NAME_MAX 255
#define BTRFS_PATH_NAME_MAX 4087

struct btrfs_ioctl_search_key {
	/* which root are we searching.  0 is the tree of tree roots */
	__u64 tree_id;

	/* keys returned will be >= min and <= max */
	__u64 min_objectid;
	__u64 max_objectid;

	/* keys returned will be >= min and <= max */
	__u64 min_offset;
	__u64 max_offset;

	/* max and min transids to search for */
	__u64 min_transid;
	__u64 max_transid;

	/* keys returned will be >= min and <= max */
	__u32 min_type;
	__u32 max_type;

	/*
	 * how many items did userland ask for, and how many are we
	 * returning
	 */
	__u32 nr_items;

	/* align to 64 bits */
	__u32 unused;

	/* some extra for later */
	__u64 unused1;
	__u64 unused2;
	__u64 unused3;
	__u64 unused4;
};

struct btrfs_ioctl_search_header {
	__u64 transid;
	__u64 objectid;
	__u64 offset;
	__u32 type;
	__u32 len;
} __attribute__((may_alias));

#define BTRFS_SEARCH_ARGS_BUFSIZE (4096 - sizeof(struct btrfs_ioctl_search_key))
/*
 * the buf is an array of search headers where
 * each header is followed by the actual item
 * the type field is expanded to 32 bits for alignment
 */
struct btrfs_ioctl_search_args {
	struct btrfs_ioctl_search_key key;
	char buf[BTRFS_SEARCH_ARGS_BUFSIZE];
};

#define BTRFS_IOC_TREE_SEARCH _IOWR(BTRFS_IOCTL_MAGIC, 17, \
                                   struct btrfs_ioctl_search_args)

