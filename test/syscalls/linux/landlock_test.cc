// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)

enum landlock_rule_type {
  LANDLOCK_RULE_PATH_BENEATH = 1,
};

struct landlock_ruleset_attr {
  uint64_t handled_access_fs;
};

struct landlock_path_beneath_attr {
  uint64_t allowed_access;
  int32_t parent_fd;
} __attribute__((packed));

#define LANDLOCK_ACCESS_FS_EXECUTE			(1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE			(1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE			(1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR			(1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR			(1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE			(1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR			(1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR			(1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG			(1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK			(1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO			(1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK			(1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM			(1ULL << 12)

// Mask for ABI v1
#define LANDLOCK_MASK_ACCESS_FS_V1 0x1fffULL

namespace gvisor {
namespace testing {

namespace {

int landlock_create_ruleset(const struct landlock_ruleset_attr* attr,
                            size_t size, uint32_t flags) {
  return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

int landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type,
                      const void* rule_attr, uint32_t flags) {
  return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
                 flags);
}

int landlock_restrict_self(int ruleset_fd, uint32_t flags) {
  return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

TEST(LandlockTest, CreateRulesetVersion) {
  int abi = landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
  // We expect ABI v1 or higher if supported by host, but in gVisor we specifically
  // want to test our implementation which should return 1 if we only implement v1.
  // If we run on native host it might return higher, but gVisor test runner will run it on gVisor.
  // For native test run, it might be > 1.
  EXPECT_THAT(abi, SyscallSucceedsWithValue(::testing::Ge(1)));
}

TEST(LandlockTest, CreateRulesetInvalidFlags) {
  // Invalid flags (not VERSION and not 0)
  EXPECT_THAT(landlock_create_ruleset(nullptr, 0, 1 << 2),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockTest, CreateRulesetInvalidSize) {
  struct landlock_ruleset_attr attr = {0};
  // Size too small (must be at least 8 bytes for handled_access_fs)
  EXPECT_THAT(landlock_create_ruleset(&attr, 4, 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockTest, CreateRulesetInvalidAccessFs) {
  // Use a flag that is not in ABI v1 (e.g., 1ULL << 15 which is IOCTL_DEV in newer ABIs)
  struct landlock_ruleset_attr attr = {1ULL << 15};
  // If we only support ABI v1, this should fail with EINVAL.
  // Note: if run on host with newer kernel, this might succeed.
  // But for gVisor (which only implements v1) it should fail.
  // We will see how to handle host vs gvisor divergence if needed, but since
  // the requirement is "implement Landlock ABIs v1", we assume gVisor will reject it.
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockTest, CreateRulesetValid) {
  struct landlock_ruleset_attr attr = {LANDLOCK_MASK_ACCESS_FS_V1};
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);
}

TEST(LandlockTest, AddRuleInvalidFD) {
  struct landlock_path_beneath_attr path_attr = {
      .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
      .parent_fd = -1,
  };
  EXPECT_THAT(landlock_add_rule(-1, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
              SyscallFailsWithErrno(EBADF));
}

TEST(LandlockTest, AddRuleInvalidType) {
  struct landlock_ruleset_attr attr = {LANDLOCK_MASK_ACCESS_FS_V1};
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());

  struct landlock_path_beneath_attr path_attr = {
      .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
      .parent_fd = -1,
  };
  // Invalid rule type 0
  EXPECT_THAT(landlock_add_rule(ruleset_fd, static_cast<enum landlock_rule_type>(0), &path_attr, 0),
              SyscallFailsWithErrno(EINVAL));
  close(ruleset_fd);
}

TEST(LandlockTest, RestrictSelfNoPrivs) {
  struct landlock_ruleset_attr attr = {LANDLOCK_MASK_ACCESS_FS_V1};
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());

  // We need to ensure we don't have CAP_SYS_ADMIN and no_new_privs is not set.
  // In gVisor test environment, we might have CAP_SYS_ADMIN.
  // Let's check and drop it if we have it.
  bool has_sys_admin = false;
  auto has_sys_admin_or_err = HaveCapability(CAP_SYS_ADMIN);
  if (has_sys_admin_or_err.ok()) {
    has_sys_admin = has_sys_admin_or_err.ValueOrDie();
  }

  // We also need to make sure no_new_privs is NOT set.
  // But we cannot unset it if it is already set.
  // Usually it is not set by default.
  
  if (has_sys_admin) {
    AutoCapability cap(CAP_SYS_ADMIN, false);
    EXPECT_THAT(landlock_restrict_self(ruleset_fd, 0),
                SyscallFailsWithErrno(EPERM));
  } else {
    EXPECT_THAT(landlock_restrict_self(ruleset_fd, 0),
                SyscallFailsWithErrno(EPERM));
  }

  close(ruleset_fd);
}

TEST(LandlockTest, RestrictSelfWithNoNewPrivs) {
  struct landlock_ruleset_attr attr = {LANDLOCK_MASK_ACCESS_FS_V1};
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());

  // Set no_new_privs
  ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), SyscallSucceeds());

  // Now it should succeed even without CAP_SYS_ADMIN (which we might or might not have)
  EXPECT_THAT(landlock_restrict_self(ruleset_fd, 0), SyscallSucceeds());

  close(ruleset_fd);
}

TEST(LandlockTest, EnforceReadWrite) {
  auto base_dir_or_err = TempPath::CreateDir();
  ASSERT_THAT(base_dir_or_err, IsPosixErrorOk());
  auto base_dir = base_dir_or_err.ValueOrDie();

  auto allowed_dir_or_err = TempPath::CreateDirWith(base_dir.path(), 0755);
  ASSERT_THAT(allowed_dir_or_err, IsPosixErrorOk());
  auto allowed_dir = allowed_dir_or_err.ValueOrDie();

  auto denied_dir_or_err = TempPath::CreateDirWith(base_dir.path(), 0755);
  ASSERT_THAT(denied_dir_or_err, IsPosixErrorOk());
  auto denied_dir = denied_dir_or_err.ValueOrDie();

  auto allowed_file_or_err = TempPath::CreateFileWith(allowed_dir.path(), "allowed", 0644);
  ASSERT_THAT(allowed_file_or_err, IsPosixErrorOk());
  auto allowed_file = allowed_file_or_err.ValueOrDie();

  auto denied_file_or_err = TempPath::CreateFileWith(denied_dir.path(), "denied", 0644);
  ASSERT_THAT(denied_file_or_err, IsPosixErrorOk());
  auto denied_file = denied_file_or_err.ValueOrDie();

  std::string allowed_dir_path = allowed_dir.path();
  std::string allowed_file_path = allowed_file.path();
  std::string denied_file_path = denied_file.path();

  auto res = InForkedProcess([allowed_dir_path, allowed_file_path, denied_file_path]() {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
    };
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_CHECK(ruleset_fd >= 0);

    int allowed_fd = open(allowed_dir_path.c_str(), O_PATH | O_DIRECTORY);
    TEST_CHECK(allowed_fd >= 0);

    struct landlock_path_beneath_attr path_attr = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
        .parent_fd = allowed_fd,
    };
    TEST_CHECK(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) == 0);
    close(allowed_fd);

    TEST_CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    TEST_CHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
    close(ruleset_fd);

    int fd = open(allowed_file_path.c_str(), O_RDONLY);
    TEST_CHECK(fd >= 0);
    close(fd);

    TEST_CHECK(open(allowed_file_path.c_str(), O_WRONLY) == -1 && errno == EACCES);
    TEST_CHECK(open(denied_file_path.c_str(), O_RDONLY) == -1 && errno == EACCES);
    TEST_CHECK(open(denied_file_path.c_str(), O_WRONLY) == -1 && errno == EACCES);
  });

  ASSERT_THAT(res, IsPosixErrorOk());
  EXPECT_EQ(res.ValueOrDie(), 0);
}

TEST(LandlockTest, EnforceRefer) {
  auto base_dir_or_err = TempPath::CreateDir();
  ASSERT_THAT(base_dir_or_err, IsPosixErrorOk());
  auto base_dir = base_dir_or_err.ValueOrDie();

  auto dir1_or_err = TempPath::CreateDirWith(base_dir.path(), 0755);
  ASSERT_THAT(dir1_or_err, IsPosixErrorOk());
  auto dir1 = dir1_or_err.ValueOrDie();

  auto dir2_or_err = TempPath::CreateDirWith(base_dir.path(), 0755);
  ASSERT_THAT(dir2_or_err, IsPosixErrorOk());
  auto dir2 = dir2_or_err.ValueOrDie();

  std::string file1_path = JoinPath(dir1.path(), "file1");
  int fd = open(file1_path.c_str(), O_CREAT | O_WRONLY, 0644);
  ASSERT_THAT(fd, SyscallSucceedsWithValue(::testing::Ge(0)));
  close(fd);

  std::string file1_rename_same = JoinPath(dir1.path(), "file1_rename");
  std::string file1_rename_cross = JoinPath(dir2.path(), "file1_rename");

  std::string dir1_path = dir1.path();

  auto res = InForkedProcess([dir1_path, file1_path, file1_rename_same, file1_rename_cross]() {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
    };
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_CHECK(ruleset_fd >= 0);

    TEST_CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    TEST_CHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
    close(ruleset_fd);

    TEST_CHECK(rename(file1_path.c_str(), file1_rename_same.c_str()) == 0);
    TEST_CHECK(rename(file1_rename_same.c_str(), file1_rename_cross.c_str()) == -1 && errno == EXDEV);
  });

  ASSERT_THAT(res, IsPosixErrorOk());
  EXPECT_EQ(res.ValueOrDie(), 0);

  unlink(file1_path.c_str());
  unlink(file1_rename_same.c_str());
  unlink(file1_rename_cross.c_str());
}

TEST(LandlockTest, EnforceMkdirUnlink) {
  auto base_dir_or_err = TempPath::CreateDir();
  ASSERT_THAT(base_dir_or_err, IsPosixErrorOk());
  auto base_dir = base_dir_or_err.ValueOrDie();

  auto allowed_dir_or_err = TempPath::CreateDirWith(base_dir.path(), 0755);
  ASSERT_THAT(allowed_dir_or_err, IsPosixErrorOk());
  auto allowed_dir = allowed_dir_or_err.ValueOrDie();

  auto denied_dir_or_err = TempPath::CreateDirWith(base_dir.path(), 0755);
  ASSERT_THAT(denied_dir_or_err, IsPosixErrorOk());
  auto denied_dir = denied_dir_or_err.ValueOrDie();

  std::string allowed_dir_path = allowed_dir.path();
  std::string denied_dir_path = denied_dir.path();

  auto res = InForkedProcess([allowed_dir_path, denied_dir_path]() {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_MAKE_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_FILE |
                             LANDLOCK_ACCESS_FS_MAKE_REG,
    };
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_CHECK(ruleset_fd >= 0);

    int allowed_fd = open(allowed_dir_path.c_str(), O_PATH | O_DIRECTORY);
    TEST_CHECK(allowed_fd >= 0);

    struct landlock_path_beneath_attr path_attr = {
        .allowed_access = LANDLOCK_ACCESS_FS_MAKE_DIR |
                          LANDLOCK_ACCESS_FS_REMOVE_DIR |
                          LANDLOCK_ACCESS_FS_REMOVE_FILE |
                          LANDLOCK_ACCESS_FS_MAKE_REG,
        .parent_fd = allowed_fd,
    };
    TEST_CHECK(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) == 0);
    close(allowed_fd);

    TEST_CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    TEST_CHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
    close(ruleset_fd);

    // Test Mkdir
    std::string allowed_subdir = JoinPath(allowed_dir_path, "subdir");
    TEST_CHECK(mkdir(allowed_subdir.c_str(), 0755) == 0);

    std::string denied_subdir = JoinPath(denied_dir_path, "subdir");
    TEST_CHECK(mkdir(denied_subdir.c_str(), 0755) == -1 && errno == EACCES);

    // Test Rmdir
    TEST_CHECK(rmdir(allowed_subdir.c_str()) == 0);
    // Try to rmdir the denied_dir itself (which is outside allowed hierarchy)
    TEST_CHECK(rmdir(denied_dir_path.c_str()) == -1 && errno == EACCES);

    // Test MakeReg & Unlink
    std::string allowed_file = JoinPath(allowed_dir_path, "file");
    int fd = open(allowed_file.c_str(), O_CREAT | O_WRONLY, 0644);
    TEST_CHECK(fd >= 0);
    close(fd);
    TEST_CHECK(unlink(allowed_file.c_str()) == 0);

    std::string denied_file = JoinPath(denied_dir_path, "file");
    TEST_CHECK(open(denied_file.c_str(), O_CREAT | O_WRONLY, 0644) == -1 && errno == EACCES);
  });

  ASSERT_THAT(res, IsPosixErrorOk());
  EXPECT_EQ(res.ValueOrDie(), 0);
}

TEST(LandlockTest, EnforceLink) {
  auto base_dir_or_err = TempPath::CreateDir();
  ASSERT_THAT(base_dir_or_err, IsPosixErrorOk());
  auto base_dir = base_dir_or_err.ValueOrDie();

  auto dir1_or_err = TempPath::CreateDirWith(base_dir.path(), 0755);
  ASSERT_THAT(dir1_or_err, IsPosixErrorOk());
  auto dir1 = dir1_or_err.ValueOrDie();

  auto dir2_or_err = TempPath::CreateDirWith(base_dir.path(), 0755);
  ASSERT_THAT(dir2_or_err, IsPosixErrorOk());
  auto dir2 = dir2_or_err.ValueOrDie();

  std::string file1_path = JoinPath(dir1.path(), "file1");
  int fd = open(file1_path.c_str(), O_CREAT | O_WRONLY, 0644);
  ASSERT_THAT(fd, SyscallSucceedsWithValue(::testing::Ge(0)));
  close(fd);

  std::string file1_link_same = JoinPath(dir1.path(), "file1_link");
  std::string file1_link_cross = JoinPath(dir2.path(), "file1_link");

  std::string dir1_path = dir1.path();

  auto res = InForkedProcess([dir1_path, file1_path, file1_link_same, file1_link_cross]() {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
    };
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    TEST_CHECK(ruleset_fd >= 0);

    TEST_CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    TEST_CHECK(landlock_restrict_self(ruleset_fd, 0) == 0);
    close(ruleset_fd);

    // Same directory link should succeed
    TEST_CHECK(link(file1_path.c_str(), file1_link_same.c_str()) == 0);
    // Cross directory link should fail with EXDEV in ABI v1
    TEST_CHECK(link(file1_link_same.c_str(), file1_link_cross.c_str()) == -1 && errno == EXDEV);
  });

  ASSERT_THAT(res, IsPosixErrorOk());
  EXPECT_EQ(res.ValueOrDie(), 0);

  unlink(file1_path.c_str());
  unlink(file1_link_same.c_str());
  unlink(file1_link_cross.c_str());
}

TEST(LandlockTest, NestedDomains) {
  auto base_dir_or_err = TempPath::CreateDir();
  ASSERT_THAT(base_dir_or_err, IsPosixErrorOk());
  auto base_dir = base_dir_or_err.ValueOrDie();

  auto dir1_or_err = TempPath::CreateDirWith(base_dir.path(), 0755);
  ASSERT_THAT(dir1_or_err, IsPosixErrorOk());
  auto dir1 = dir1_or_err.ValueOrDie();

  auto dir2_or_err = TempPath::CreateDirWith(base_dir.path(), 0755);
  ASSERT_THAT(dir2_or_err, IsPosixErrorOk());
  auto dir2 = dir2_or_err.ValueOrDie();

  auto file1_or_err = TempPath::CreateFileWith(dir1.path(), "file1", 0644);
  ASSERT_THAT(file1_or_err, IsPosixErrorOk());
  auto file1 = file1_or_err.ValueOrDie();

  auto file2_or_err = TempPath::CreateFileWith(dir2.path(), "file2", 0644);
  ASSERT_THAT(file2_or_err, IsPosixErrorOk());
  auto file2 = file2_or_err.ValueOrDie();

  std::string base_dir_path = base_dir.path();
  std::string dir1_path = dir1.path();
  std::string file1_path = file1.path();
  std::string file2_path = file2.path();

  auto res = InForkedProcess([base_dir_path, dir1_path, file1_path, file2_path]() {
    // Ruleset 1: allows base_dir
    struct landlock_ruleset_attr attr1 = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
    };
    int ruleset_fd1 = landlock_create_ruleset(&attr1, sizeof(attr1), 0);
    TEST_CHECK(ruleset_fd1 >= 0);

    int base_fd = open(base_dir_path.c_str(), O_PATH | O_DIRECTORY);
    TEST_CHECK(base_fd >= 0);

    struct landlock_path_beneath_attr path_attr1 = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
        .parent_fd = base_fd,
    };
    TEST_CHECK(landlock_add_rule(ruleset_fd1, LANDLOCK_RULE_PATH_BENEATH, &path_attr1, 0) == 0);
    close(base_fd);

    TEST_CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    TEST_CHECK(landlock_restrict_self(ruleset_fd1, 0) == 0);
    close(ruleset_fd1);

    // Verify we can read both files
    int fd1 = open(file1_path.c_str(), O_RDONLY);
    TEST_CHECK(fd1 >= 0);
    close(fd1);
    int fd2 = open(file2_path.c_str(), O_RDONLY);
    TEST_CHECK(fd2 >= 0);
    close(fd2);

    // Ruleset 2: allows only dir1
    struct landlock_ruleset_attr attr2 = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
    };
    int ruleset_fd2 = landlock_create_ruleset(&attr2, sizeof(attr2), 0);
    TEST_CHECK(ruleset_fd2 >= 0);

    int dir1_fd = open(dir1_path.c_str(), O_PATH | O_DIRECTORY);
    TEST_CHECK(dir1_fd >= 0);

    struct landlock_path_beneath_attr path_attr2 = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
        .parent_fd = dir1_fd,
    };
    TEST_CHECK(landlock_add_rule(ruleset_fd2, LANDLOCK_RULE_PATH_BENEATH, &path_attr2, 0) == 0);
    close(dir1_fd);

    TEST_CHECK(landlock_restrict_self(ruleset_fd2, 0) == 0);
    close(ruleset_fd2);

    // Now file1 should be readable, but file2 should not
    fd1 = open(file1_path.c_str(), O_RDONLY);
    TEST_CHECK(fd1 >= 0);
    close(fd1);

    TEST_CHECK(open(file2_path.c_str(), O_RDONLY) == -1 && errno == EACCES);
  });

  ASSERT_THAT(res, IsPosixErrorOk());
  EXPECT_EQ(res.ValueOrDie(), 0);
}

TEST(LandlockTest, AddRuleInvalidRuleset) {
  struct landlock_path_beneath_attr path_attr = {
      .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
      .parent_fd = -1,
  };
  // EBADF for non-existent FD
  EXPECT_THAT(landlock_add_rule(9999, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
              SyscallFailsWithErrno(EBADF));

  // EINVAL for valid FD that is not a landlock ruleset
  int dev_null = open("/dev/null", O_RDONLY);
  ASSERT_THAT(dev_null, SyscallSucceeds());
  EXPECT_THAT(landlock_add_rule(dev_null, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
              SyscallFailsWithErrno(EINVAL));
  close(dev_null);
}

TEST(LandlockTest, RestrictSelfInvalidRuleset) {
  // EBADF for non-existent FD
  EXPECT_THAT(landlock_restrict_self(9999, 0),
              SyscallFailsWithErrno(EBADF));

  // EINVAL for valid FD that is not a landlock ruleset
  int dev_null = open("/dev/null", O_RDONLY);
  ASSERT_THAT(dev_null, SyscallSucceeds());
  EXPECT_THAT(landlock_restrict_self(dev_null, 0),
              SyscallFailsWithErrno(EINVAL));
  close(dev_null);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
