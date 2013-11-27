
int setup_cgroup_mounts(void);
bool compute_pid_cgroup(pid_t pid, const char *controller, const char *cgroup, char *path);
bool may_access(pid_t pid, uid_t uid, gid_t gid, const char *path, int mode);
void get_pid_creds(pid_t pid, uid_t *uid, gid_t *gid);
char *file_read_string(const char *path);
void get_pid_creds(pid_t pid, uid_t *uid, gid_t *gid);
