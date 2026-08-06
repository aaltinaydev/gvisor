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

// Landlock syscall tests (ABI v1).

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/landlock_util.h"
#include "test/util/capability_util.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(LandlockV1Test, AbiVersionIsSupported) {
  int version = LandlockAbiVersion();
  SKIP_IF(version < 0 && errno == ENOSYS);
  ASSERT_GE(version, 1) << "unexpected Landlock ABI version";
}

TEST(LandlockV1Test, CreateRulesetHandlingAllV1RightsSucceeds) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = kFsAccessV1;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) {
    close(fd);
  }
}

TEST(LandlockV1Test, CreateRulesetRejectsUnknownFlags) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), /*flags=*/0xffff),
              SyscallFailsWithErrno(EINVAL));
}

// LANDLOCK_CREATE_RULESET_ERRATA reports a bitmask of the errata an
// implementation has fixed. Any non-negative value is a valid answer; zero
// means "none reported". Implementations that predate the flag reject it.
TEST(LandlockV1Test, CreateRulesetErrataReturnsBitmask) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int rc = landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_ERRATA);
  if (rc < 0) {
    EXPECT_EQ(errno, EINVAL) << "unexpected errno " << errno;
  } else {
    EXPECT_GE(rc, 0);
  }
}

// The errata query takes no ruleset, so passing one is an error.
TEST(LandlockV1Test, CreateRulesetErrataRejectsAttr) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_MAKE_REG;
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr),
                                      LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(
      landlock_create_ruleset(nullptr, sizeof(attr),
                              LANDLOCK_CREATE_RULESET_ERRATA),
      SyscallFailsWithErrno(EINVAL));
}

// The query flags are mutually exclusive.
TEST(LandlockV1Test, CreateRulesetVersionAndErrataRejected) {
  SKIP_IF(LandlockAbiVersion() < 1);
  EXPECT_THAT(landlock_create_ruleset(
                  nullptr, 0,
                  LANDLOCK_CREATE_RULESET_VERSION |
                      LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockV1Test, CreateRulesetRejectsUnknownAccessBits) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = (1ULL << 63);
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockV1Test, AddRuleRejectsUnknownRuleType) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  EXPECT_THAT(landlock_add_rule(fd, static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EINVAL));
  close(fd);
}

TEST(LandlockV1Test, AddPathBeneathRejectsUnhandledAccess) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  int parent_fd = open(dir.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EINVAL));
  close(parent_fd);
  close(fd);
}

TEST(LandlockV1Test, RestrictSelfWithoutNoNewPrivsFails) {
  SKIP_IF(LandlockAbiVersion() < 1);
  AutoCapability cap_admin(CAP_SYS_ADMIN, false);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(fd, 0) < 0 && errno == EPERM ? kDenied
                                                              : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied);
}

TEST(LandlockV1Test, RestrictSelfRejectsBadFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(-1, 0) < 0 && errno == EBADF ? kDenied
                                                              : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied);
}

TEST(LandlockV1Test, ReadOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ReadInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictionInheritedAcrossFork) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    pid_t pid = fork();
    if (pid == 0) {
      _exit(TryReadOpen(target));
    }
    int st;
    if (waitpid(pid, &st, 0) < 0) {
      _exit(kSetup);
    }
    _exit(WIFEXITED(st) ? WEXITSTATUS(st) : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, LayeredRulesetsOnlyIntersect) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
    EnforceOrDie(fd);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, WriteFileOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_WRITE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_WRONLY);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, WriteFileInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_WRITE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_WRONLY);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ReadDirOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_DIR, allowed,
                  LANDLOCK_ACCESS_FS_READ_DIR);
    int fd = open(target.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, MakeRegOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = JoinPath(root.path(), "new_file");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_REG);
    int fd = open(target.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, MakeRegInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = JoinPath(allowed_dir.path(), "new_file");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_REG);
    int fd = open(target.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, MakeDirOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = JoinPath(root.path(), "new_dir");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_DIR, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyFs(mkdir(target.c_str(), 0700)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RemoveFileOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyFs(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RemoveFileInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyFs(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RemoveDirOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_DIR, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyFs(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RemoveDirInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath inside_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside_dir.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_DIR, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyFs(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExecuteOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(root.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE, allowed,
                  LANDLOCK_ACCESS_FS_EXECUTE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Landlock ABI v1 has no LANDLOCK_ACCESS_FS_REFER right, so rename(2) and
// link(2) between two directories are refused with EXDEV rather than EACCES.
constexpr int kExdev = 103;

int ClassifyRefer(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  if (errno == EACCES) {
    return kDenied;
  }
  if (errno == EXDEV) {
    return kExdev;
  }
  return kOther;
}

// Enforces a policy handling handled_access and granting access1 beneath dir1
// and access2 beneath dir2. A zero access grants nothing for that directory.
void ApplyTwoDirPolicy(uint64_t handled_access, const std::string& dir1,
                       uint64_t access1, const std::string& dir2,
                       uint64_t access2) {
  int fd = CreateRuleset(handled_access);
  if (access1 != 0) {
    AddPathRule(fd, dir1, access1);
  }
  if (access2 != 0) {
    AddPathRule(fd, dir2, access2);
  }
  EnforceOrDie(fd);
}

// Renaming a regular file within one directory needs both the right to create
// the file and the right to remove it.
TEST(LandlockV1Test, RenameSameDirAllowedWithMakeRegAndRemoveFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "renamed");
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, kRights);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RenameSameDirDeniedWithoutRemoveFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "renamed");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
        LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RenameSameDirDeniedWithoutMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "renamed");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
        LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// A domain that handles none of the rights a rename needs does not constrain
// it.
TEST(LandlockV1Test, RenameSameDirAllowedWhenRightsUnhandled) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "renamed");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_DIR);
    EnforceOrDie(fd);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Renaming over an existing file also needs the right to remove the file being
// replaced.
TEST(LandlockV1Test, RenameOverExistingFileDeniedWithoutRemoveFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  TempPath dst_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = dst_file.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
        LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RenameOverExistingFileAllowedWithBothRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  TempPath dst_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = dst_file.release();
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, kRights);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Renaming a directory needs the directory-flavored rights.
TEST(LandlockV1Test, RenameDirSameDirRequiresMakeDirAndRemoveDir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(allowed));
  const std::string src = src_dir.release();
  const std::string dst = JoinPath(allowed, "renamed_dir");
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, kRights);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RenameDirSameDirDeniedWithoutRemoveDir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(allowed));
  const std::string src = src_dir.release();
  const std::string dst = JoinPath(allowed, "renamed_dir");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR,
                  allowed, LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Renaming a symlink is governed by MAKE_SYM, not MAKE_REG: the right depends
// on the type of the file being moved, and the symlink itself is not followed.
TEST(LandlockV1Test, RenameSymlinkSameDirRequiresMakeSym) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_link =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(allowed, "target"));
  const std::string src = src_link.release();
  const std::string dst = JoinPath(allowed, "renamed_link");
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REMOVE_FILE;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, kRights);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Granting MAKE_REG instead of MAKE_SYM is not enough, which is what
// distinguishes this from the regular-file case.
TEST(LandlockV1Test, RenameSymlinkSameDirDeniedWithOnlyMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_link =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateSymlinkTo(allowed, "target"));
  const std::string src = src_link.release();
  const std::string dst = JoinPath(allowed, "renamed_link");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_MAKE_REG |
                      LANDLOCK_ACCESS_FS_REMOVE_FILE,
                  allowed,
                  LANDLOCK_ACCESS_FS_MAKE_REG |
                      LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Reparenting is not expressible in ABI v1, so it is refused outright even when
// every v1 right is granted on both directories.
TEST(LandlockV1Test, RenameAcrossDirectoriesRefusedWithExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(to, "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from, kFsAccessV1, to, kFsAccessV1);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kExdev)
      << "exit status " << status;
}

// The refusal does not depend on which rights the domain handles: merely having
// a domain is enough.
TEST(LandlockV1Test, RenameAcrossDirectoriesRefusedWhenRightsUnhandled) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(to_dir.path(), "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_DIR);
    EnforceOrDie(fd);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kExdev)
      << "exit status " << status;
}

// link(2) needs the right to create the file, but not the right to remove it:
// the source stays where it is.
TEST(LandlockV1Test, LinkSameDirAllowedWithMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "hardlink");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, LinkSameDirDoesNotRequireRemoveFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "hardlink");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
        LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, LinkSameDirDeniedWithoutMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(allowed, "hardlink");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kFsAccessV1);
    EnforceOrDie(fd);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, LinkAcrossDirectoriesRefusedWithExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from));
  const std::string src = src_file.release();
  const std::string dst = JoinPath(to, "hardlink");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from, kFsAccessV1, to, kFsAccessV1);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kExdev)
      << "exit status " << status;
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
