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
#include <mqueue.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/syscalls/linux/landlock_util.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

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

TEST(LandlockV1Test, CreateRulesetErrataReturnsBitmask) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int rc = landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_ERRATA);
  if (rc < 0) {
    EXPECT_EQ(errno, EINVAL) << "unexpected errno " << errno;
  } else {
    EXPECT_GE(rc, 0);
  }
}

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

TEST(LandlockV1Test, CreateRulesetEmptyFsWithUnknownNetBitsIsNotEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_net = (1ULL << 63);
  int rc = landlock_create_ruleset(&attr, sizeof(attr), 0);
  EXPECT_LT(rc, 0);
  EXPECT_NE(errno, ENOMSG) << "empty handled_access_fs was reported before "
                              "the unknown bits elsewhere in the attr";
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
}

TEST(LandlockV1Test, CreateRulesetNullAttrReturnsEfault) {
  SKIP_IF(LandlockAbiVersion() < 1);
  EXPECT_THAT(landlock_create_ruleset(nullptr, 0, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(landlock_create_ruleset(nullptr, 7, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(
      landlock_create_ruleset(nullptr, sizeof(landlock_ruleset_attr), 0),
      SyscallFailsWithErrno(EFAULT));
}

TEST(LandlockV1Test, CreateRulesetSizeHandling) {
  SKIP_IF(LandlockAbiVersion() < 1);
  uint64_t fs_only = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(landlock_create_ruleset(
                  reinterpret_cast<landlock_ruleset_attr*>(&fs_only), 7, 0),
              SyscallFailsWithErrno(EINVAL));
  int fd = landlock_create_ruleset(
      reinterpret_cast<landlock_ruleset_attr*>(&fs_only), sizeof(fs_only), 0);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) {
    close(fd);
  }
  const long page_size = sysconf(_SC_PAGESIZE);
  std::vector<char> big(page_size + 8, 0);
  memcpy(big.data(), &fs_only, sizeof(fs_only));
  EXPECT_THAT(landlock_create_ruleset(
                  reinterpret_cast<landlock_ruleset_attr*>(big.data()),
                  big.size(), 0),
              SyscallFailsWithErrno(E2BIG));
  std::vector<char> tail(sizeof(landlock_ruleset_attr) + 8, 0);
  memcpy(tail.data(), &fs_only, sizeof(fs_only));
  tail[tail.size() - 1] = 1;
  int rc = landlock_create_ruleset(
      reinterpret_cast<landlock_ruleset_attr*>(tail.data()), tail.size(), 0);
  EXPECT_LT(rc, 0);
  EXPECT_THAT(errno, ::testing::AnyOf(E2BIG, EINVAL));
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
  landlock_ruleset_attr full = {};
  full.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  full.scoped = (1ULL << 63);
  rc = landlock_create_ruleset(&full, sizeof(full), 0);
  EXPECT_LT(rc, 0);
  EXPECT_THAT(errno, ::testing::AnyOf(E2BIG, EINVAL));
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
}

TEST(LandlockV1Test, CreateRulesetEmptyHandledAccessReturnsEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
              SyscallFailsWithErrno(ENOMSG));
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

TEST(LandlockV1Test, AddRuleBadFdWithBadRuleTypeReportsBadFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_path_beneath_attr path_beneath = {};
  EXPECT_THAT(landlock_add_rule(-1, static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EBADF));

  int file_fd = open("/", O_RDONLY | O_CLOEXEC);
  ASSERT_THAT(file_fd, SyscallSucceeds());
  EXPECT_THAT(landlock_add_rule(file_fd,
                                static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EBADFD));
  close(file_fd);
}

TEST(LandlockV1Test, AddRuleEmptyAllowedAccessReturnsEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.parent_fd = -1;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(ENOMSG));
  close(fd);
}

TEST(LandlockV1Test, AddRuleUnknownFlagsReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int parent_fd = open(dir.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 2),
      SyscallFailsWithErrno(EINVAL));
  close(parent_fd);
  close(fd);
}

TEST(LandlockV1Test, AddRuleDirOnlyRightsOnNonDirectoryReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs =
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  int parent_fd = open(file.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_DIR;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EINVAL));
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallSucceeds());
  close(parent_fd);
  close(fd);
}

TEST(LandlockV1Test, RulesetFdRejectsIO) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  char c;
  EXPECT_THAT(read(fd, &c, 1), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(write(fd, &c, 1), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(lseek(fd, 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
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

TEST(LandlockV1Test, AddPathBeneathRejectsInternalMountFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  auto close_ruleset = Cleanup([fd] { close(fd); });

  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;

  int memfd = syscall(SYS_memfd_create, "landlock_v1_test", 0);
  ASSERT_THAT(memfd, SyscallSucceeds());
  path_beneath.parent_fd = memfd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(memfd);

  int ns_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  if (ns_fd >= 0) {
    path_beneath.parent_fd = ns_fd;
    EXPECT_THAT(
        landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
        SyscallFailsWithErrno(EBADFD));
    close(ns_fd);
  }

  int sv[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), SyscallSucceeds());
  path_beneath.parent_fd = sv[0];
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(sv[0]);
  close(sv[1]);
}

TEST(LandlockV1Test, ProcFdReopenOfPipeIsExempt) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fds[2];
    if (pipe(fds) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    const std::string path = "/proc/self/fd/" + std::to_string(fds[0]);
    _exit(TryReadOpen(path));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, HostFdsAreInternal) {
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open("/proc/self/fd/2", O_WRONLY);
    _exit(fd >= 0 ? kAllowed : kSetup);
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kAllowed));

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  path_beneath.parent_fd = 2;
  EXPECT_THAT(
      landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath,
                        0),
      SyscallFailsWithErrno(EBADFD));
  close(ruleset_fd);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    int fd = open("/proc/self/fd/2", O_WRONLY);
    if (fd >= 0) {
      _exit(kAllowed);
    }
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
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

TEST(LandlockV1Test, RestrictSelfWithoutNoNewPrivsReportsEpermNotEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  AutoCapability cap_admin(CAP_SYS_ADMIN, false);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    _exit(landlock_restrict_self(-1, ~0u) < 0 && errno == EPERM ? kDenied
                                                                : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictSelfUnknownFlagsWithNoNewPrivsReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(fd, 1u << 31) < 0 && errno == EINVAL
              ? kDenied
              : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictSelfWithCapSysAdminWithoutNoNewPrivs) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    if (landlock_restrict_self(fd, 0) != 0) {
      _exit(kSetup);
    }
    close(fd);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, MaxSixteenStackedLayers) {
  SKIP_IF(LandlockAbiVersion() < 1);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    for (int i = 0; i < 16; i++) {
      int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR);
      if (landlock_restrict_self(fd, 0) != 0) {
        _exit(kSetup);
      }
      close(fd);
    }
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR);
    int rc = landlock_restrict_self(fd, 0);
    close(fd);
    _exit(rc < 0 && errno == E2BIG ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
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

TEST(LandlockV1Test, OpenWithFourthAccessModeRequiresNoRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE |
                            LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_ACCMODE);
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


enum ErrnoResult {
  kErrOk = 0,
  kErrRofs = 110,
  kErrNoent = 111,
  kErrAcces = 112,
  kErrPerm = 113,
  kErrIsdir = 114,
  kErrNotdir = 115,
  kErrNotempty = 116,
  kErrInval = 117,
  kErrExist = 118,
  kErrUnexpected = 119,
  kErrExdev = 120,
};

int ClassifyErrno(int rc) {
  if (rc >= 0) {
    return kErrOk;
  }
  switch (errno) {
    case EROFS:
      return kErrRofs;
    case ENOENT:
      return kErrNoent;
    case EACCES:
      return kErrAcces;
    case EPERM:
      return kErrPerm;
    case EISDIR:
      return kErrIsdir;
    case ENOTDIR:
      return kErrNotdir;
    case ENOTEMPTY:
      return kErrNotempty;
    case EINVAL:
      return kErrInval;
    case EEXIST:
      return kErrExist;
    case EXDEV:
      return kErrExdev;
    default:
      return kErrUnexpected;
  }
}

TEST(LandlockV1Test, MkdirOverExistingFileReportsEexistNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath existing =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string target;
  target = existing.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyErrno(mkdir(target.c_str(), 0755)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrExist)
      << "exit status " << status;
}

TEST(LandlockV1Test, OPathOpenNeedsNoRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    int fd = open(target.c_str(), O_PATH | O_CLOEXEC);
    _exit(fd >= 0 ? kAllowed : (errno == EACCES ? kDenied : kOther));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, DeniedTruncatingOpenLeavesFileIntact) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "contents", 0644));
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_WRONLY | O_TRUNC);
    if (fd >= 0 || errno != EACCES) {
      _exit(kOther);
    }
    struct stat st;
    if (stat(target.c_str(), &st) != 0) {
      _exit(kSetup);
    }
    _exit(st.st_size == 8 ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, MknodTypesRequireMatchingMakeRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string allowed;
  allowed = dir.path();
  static std::string fifo_path;
  fifo_path = JoinPath(allowed, "fifo");
  static std::string reg_path;
  reg_path = JoinPath(allowed, "reg");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(
        LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_REG, allowed,
        LANDLOCK_ACCESS_FS_MAKE_FIFO);
    if (mkfifo(fifo_path.c_str(), 0644) != 0) {
      _exit(kOther);
    }
    int rc = mknod(reg_path.c_str(), S_IFREG | 0644, 0);
    _exit(rc < 0 && errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnixBindRequiresMakeSock) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string allowed;
  allowed = dir.path();

  auto bind_at = [](const std::string& name) -> ChildResult {
    if (chdir(allowed.c_str()) != 0) {
      return kSetup;
    }
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
      return kSetup;
    }
    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, name.c_str(), name.size() + 1);
    int rc = bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    int err = errno;
    close(sock);
    if (rc == 0) {
      return kAllowed;
    }
    return err == EACCES ? kDenied : kOther;
  };

  int denied = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_SOCK);
    _exit(bind_at("denied.sock"));
  }));
  SKIP_IF(WIFEXITED(denied) && WEXITSTATUS(denied) == kSetup);
  EXPECT_TRUE(WIFEXITED(denied) && WEXITSTATUS(denied) == kDenied)
      << "exit status " << denied;

  int granted = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_SOCK, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_SOCK);
    _exit(bind_at("granted.sock"));
  }));
  SKIP_IF(WIFEXITED(granted) && WEXITSTATUS(granted) == kSetup);
  EXPECT_TRUE(WIFEXITED(granted) && WEXITSTATUS(granted) == kAllowed)
      << "exit status " << granted;
}

TEST(LandlockV1Test, SameFileRulesInTwoLayersIntersect) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    constexpr uint64_t kHandled =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    ApplyFsPolicy(kHandled, target, LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen(target) != kAllowed) {
      _exit(kSetup);
    }
    ApplyFsPolicy(kHandled, target, LANDLOCK_ACCESS_FS_WRITE_FILE);
    if (TryReadOpen(target) != kDenied) {
      _exit(kOther);
    }
    int fd = open(target.c_str(), O_WRONLY);
    if (fd >= 0) {
      close(fd);
      _exit(kOther);
    }
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkOfMissingFileReportsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string target;
  target = JoinPath(dir.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, RmdirOfMissingDirReportsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string target;
  target = JoinPath(dir.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkWithTrailingSlashReportsEisdirNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string target;
  target = victim_dir.path() + "/";

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkOfMountPointWithTrailingSlashReportsEisdir) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath mnt_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string from;
  static std::string target;
  from = src_dir.path();
  target = mnt_dir.path() + "/";

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(from.c_str(), mnt_dir.path().c_str(), nullptr, MS_BIND,
                      nullptr) == 0);
    TEST_PCHECK(unlink(target.c_str()) < 0 && errno == EISDIR);
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkKernfsTrailingSlashReportsEisdirNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink("/proc/sys/")));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

TEST(LandlockV1Test, LinkOfProcDirectoryUnderDomainIsExdevNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);

  // Linux procfs fails the new-name lookup with ENOENT before any security
  // hook or link-support check runs; gVisor's procfs reports EPERM for the
  // unsupported link instead. Landlock's EXDEV can only take priority in the
  // latter ordering, so derive the expectation from the unrestricted errno.
  const int control =
      ClassifyErrno(link("/proc/self/task", "/proc/landlock_test_link"));
  SKIP_IF(control != kErrPerm && control != kErrNoent);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyErrno(link("/proc/self/task", "/proc/landlock_test_link")));
  }));
  const int want = control == kErrNoent ? kErrNoent : kErrExdev;
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == want)
      << "exit status " << status << " want " << want;
}

TEST(LandlockV1Test, UnlinkOfDirectoryReportsEaccesNotEisdir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string target;
  target = victim_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, RmdirOfNonDirectoryReportsEaccesNotEnotdir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  static std::string target;
  target = victim.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, RmdirOfNonEmptyDirReportsEaccesNotEnotempty) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath occupant =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(victim_dir.path()));
  static std::string target;
  target = victim_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkInStickyDirReportsEaccesNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath sticky_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(sticky_dir.path()));
  ASSERT_THAT(chmod(sticky_dir.path().c_str(), 01777), SyscallSucceeds());
  constexpr uid_t kNobody = 65534;
  static std::string target;
  target = victim.path();

  // As kNobody the caller owns neither the sticky directory nor the victim
  // and loses all capabilities, so the unrestricted unlink fails the sticky
  // check with EPERM. Dropping privileges this way rather than chown'ing the
  // files to kNobody keeps the test independent of whether ownership changes
  // are honored by the backing filesystem (they are not with shared gofer
  // file access).
  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kErrPerm));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkOnReadOnlyMountReportsErofsNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string victim = JoinPath(root, "victim");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    int fd = open(victim.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(close(fd) == 0);
    if (mount(nullptr, root.c_str(), nullptr, MS_REMOUNT | MS_RDONLY,
              nullptr) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(victim.c_str())));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrRofs)
      << "exit status " << status;
}

TEST(LandlockV1Test, MkdirOnReadOnlyProcMountReportsErofsNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string target = JoinPath(root, "newdir");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    if (mount("proc", root.c_str(), "proc", MS_RDONLY, nullptr) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyErrno(mkdir(target.c_str(), 0755)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrRofs)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkMissingPathOnReadOnlyProcMountErrnos) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  // A missing intermediate component fails the parent walk with ENOENT
  // before the read-only mount is considered, while a missing final
  // component is only looked up after mnt_want_write() and so reports EROFS.
  const std::string missing_intermediate =
      JoinPath(root, "nonexistent/victim");
  const std::string missing_final = JoinPath(root, "nonexistent");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    if (mount("proc", root.c_str(), "proc", MS_RDONLY, nullptr) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    int intermediate = ClassifyErrno(unlink(missing_intermediate.c_str()));
    if (intermediate != kErrNoent) {
      _exit(intermediate);
    }
    _exit(ClassifyErrno(unlink(missing_final.c_str())));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrRofs)
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

TEST(LandlockV1Test, ExecuteOutsideAllowedTreeDeniedWhenOnlyReadFileHandled) {
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
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExecuteInsideAllowedTreeDeniedWithoutReadFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(allowed_dir.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
                  allowed, LANDLOCK_ACCESS_FS_EXECUTE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExecuteInsideAllowedTreeAllowedWhenReadFileUnhandled) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(allowed_dir.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE, allowed,
                  LANDLOCK_ACCESS_FS_EXECUTE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

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

TEST(LandlockV1Test, RenameAcrossDirectoriesWithoutRemoveFileReportsEacces) {
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
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE, from, 0,
        to, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RenameAcrossDirectoriesWithoutMakeRegReportsEacces) {
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
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE, from,
        LANDLOCK_ACCESS_FS_REMOVE_FILE, to, 0);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RenameDirAcrossDirectoriesWithoutMakeDirReportsEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(from_dir.path()));
  const std::string src = src_dir.release();
  const std::string dst = JoinPath(to_dir.path(), "moved");
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from, LANDLOCK_ACCESS_FS_REMOVE_DIR, to,
                      LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, LinkAcrossDirectoriesWithoutRemoveFileStillReportsExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.path();
  const std::string dst = JoinPath(to_dir.path(), "linked");
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE, from, 0,
        to, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kExdev)
      << "exit status " << status;
}

TEST(LandlockV1Test, LinkAcrossDirectoriesWithoutMakeRegReportsEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.path();
  const std::string dst = JoinPath(to_dir.path(), "linked");
  const std::string from = from_dir.path();
  const std::string to = to_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(LANDLOCK_ACCESS_FS_MAKE_REG, from,
                      LANDLOCK_ACCESS_FS_MAKE_REG, to, 0);
    _exit(ClassifyRefer(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

constexpr int kEexist = 105;
constexpr int kNoReplaceUnsupported = 106;

int ClassifyNoReplace(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  switch (errno) {
    case EEXIST:
      return kEexist;
    case ENOSYS:
    case EINVAL:
      return kNoReplaceUnsupported;
    case EACCES:
      return kDenied;
    case EXDEV:
      return kExdev;
    default:
      return kOther;
  }
}

TEST(LandlockV1Test, RenameExchangeRequiresExchangeRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string allowed;
  allowed = dir.path();
  TempPath a = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  TempPath b = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  static std::string src;
  src = a.release();
  static std::string dst;
  dst = b.release();
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE;
  constexpr int kExchangeUnsupported = 107;
  auto classify = [](int rc) -> int {
    if (rc == 0) {
      return kAllowed;
    }
    switch (errno) {
      case EACCES:
        return kDenied;
      case EINVAL:
      case ENOSYS:
        return kExchangeUnsupported;
      default:
        return kOther;
    }
  };

  int granted = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, kRights);
    _exit(classify(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(),
                             RENAME_EXCHANGE)));
  }));
  SKIP_IF(WIFEXITED(granted) && WEXITSTATUS(granted) == kExchangeUnsupported);
  EXPECT_TRUE(WIFEXITED(granted) && WEXITSTATUS(granted) == kAllowed)
      << "exit status " << granted;

  int denied = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, allowed, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(classify(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(),
                             RENAME_EXCHANGE)));
  }));
  EXPECT_TRUE(WIFEXITED(denied) && WEXITSTATUS(denied) == kDenied)
      << "exit status " << denied;
}

TEST(LandlockV1Test, RenameNoReplaceOverExistingReportsEexistNotExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  TempPath dst_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(to_dir.path()));
  const std::string src = src_file.path();
  const std::string dst = dst_file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from_dir.path(), kFsAccessV1, to_dir.path(),
                      kFsAccessV1);
    _exit(ClassifyNoReplace(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
                                      dst.c_str(), RENAME_NOREPLACE)));
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_THAT(WEXITSTATUS(status),
              ::testing::AnyOf(kEexist, kNoReplaceUnsupported));
}

TEST(LandlockV1Test, RenameNoReplaceOverExistingReportsEexistNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  TempPath dst_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.path();
  const std::string dst = dst_file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_REG |
                           LANDLOCK_ACCESS_FS_REMOVE_FILE);
    EnforceOrDie(fd);
    _exit(ClassifyNoReplace(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
                                      dst.c_str(), RENAME_NOREPLACE)));
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_THAT(WEXITSTATUS(status),
              ::testing::AnyOf(kEexist, kNoReplaceUnsupported));
}

TEST(LandlockV1Test, RenameNoReplaceOntoMissingStillRefusedWithExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.path();
  const std::string dst = JoinPath(to_dir.path(), "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from_dir.path(), kFsAccessV1, to_dir.path(),
                      kFsAccessV1);
    _exit(ClassifyNoReplace(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
                                      dst.c_str(), RENAME_NOREPLACE)));
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_THAT(WEXITSTATUS(status),
              ::testing::AnyOf(kExdev, kNoReplaceUnsupported));
}

TEST(LandlockV1Test, RenameOverNonEmptyDirReportsEaccesNotEnotempty) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath occupant =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dst_dir.path()));
  static std::string src;
  static std::string dst;
  src = src_dir.path();
  dst = dst_dir.path();

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  ASSERT_TRUE(WIFEXITED(control) && WEXITSTATUS(control) == kErrNotempty)
      << "control exit status " << control;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR |
                            LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, RenameFileOverDirReportsEaccesNotEisdir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string src;
  static std::string dst;
  src = src_file.path();
  dst = dst_dir.path();

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  ASSERT_TRUE(WIFEXITED(control) && WEXITSTATUS(control) == kErrIsdir)
      << "control exit status " << control;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

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

TEST(LandlockV1Test, LinkOfUnsafeSourceReportsEpermNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  ASSERT_THAT(chmod(src_file.path().c_str(), 0644), SyscallSucceeds());
  ASSERT_THAT(chmod(dir.path().c_str(), 0777), SyscallSucceeds());
  constexpr uid_t kNobody = 65534;
  static std::string src;
  static std::string dst;
  src = src_file.path();
  dst = JoinPath(dir.path(), "hardlink");

  // As kNobody the caller does not own the source, cannot write to it
  // (0644), and has no capabilities, so with protected_hardlinks the link
  // fails may_linkat() with EPERM. may_linkat() runs before
  // security_path_link() in do_linkat(), so EPERM must still win under a
  // Landlock domain denying MAKE_REG. Dropping privileges via setresuid
  // rather than chown'ing the source to kNobody keeps the test independent
  // of whether ownership changes are honored by the backing filesystem.
  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    _exit(ClassifyErrno(link(src.c_str(), dst.c_str())));
  }));
  SKIP_IF(!WIFEXITED(control) || WEXITSTATUS(control) != kErrPerm);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyErrno(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrPerm)
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

void CreateFile(const std::string& path) {
  int fd = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  ASSERT_THAT(fd, SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());
}


TEST(LandlockV1Test, RuleReachesFileThroughHardLink) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath covered_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath other_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));

  const std::string target = JoinPath(covered_dir.path(), "target");
  ASSERT_NO_FATAL_FAILURE(CreateFile(target));
  const std::string link_path = JoinPath(other_dir.path(), "link");
  ASSERT_THAT(link(target.c_str(), link_path.c_str()), SyscallSucceeds());

  const std::string uncovered = JoinPath(other_dir.path(), "uncovered");
  ASSERT_NO_FATAL_FAILURE(CreateFile(uncovered));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, target,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen(uncovered) != kDenied) {
      _exit(kOther);
    }
    _exit(TryReadOpen(link_path));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleSurvivesRenameOfCoveredDirectory) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath covered_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string parent = root.path();
  const std::string dir = covered_dir.release();
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(dir, "f")));
  const std::string renamed = JoinPath(parent, "renamed");

  constexpr uint64_t kHandled = LANDLOCK_ACCESS_FS_READ_FILE |
                                LANDLOCK_ACCESS_FS_MAKE_DIR |
                                LANDLOCK_ACCESS_FS_REMOVE_DIR;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kHandled);
    AddPathRule(fd, dir, LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(fd, parent,
                LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR);
    EnforceOrDie(fd);

    if (rename(dir.c_str(), renamed.c_str()) != 0) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(JoinPath(renamed, "f")));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleDiesWithTheFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string target;
  target = file.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, target,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen(target) != kAllowed) {
      _exit(kSetup);
    }
    if (unlink(target.c_str()) != 0) {
      _exit(kSetup);
    }
    int fd = open(target.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
      _exit(kSetup);
    }
    close(fd);
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleSurvivesUnlinkOfOneHardLink) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string first;
  first = file.release();
  static std::string second;
  second = JoinPath(dir.path(), "second");
  ASSERT_THAT(link(first.c_str(), second.c_str()), SyscallSucceeds());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, first,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (unlink(first.c_str()) != 0) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(second));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleReachesFileThroughBindMount) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath covered_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath mount_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string dir = covered_dir.path();
  const std::string mount_point = mount_dir.path();
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(dir, "f")));
  const std::string via_mount = JoinPath(mount_point, "f");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(dir.c_str(), mount_point.c_str(), nullptr, MS_BIND,
                      nullptr) == 0);

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, dir,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(via_mount));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleOnBindMountRootReachesDisconnectedDirectory) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string src = JoinPath(root.path(), "src");
  const std::string mount_root = JoinPath(src, "a");
  const std::string dir = JoinPath(mount_root, "b");
  const std::string moved_dir = JoinPath(src, "b");
  const std::string mount_point = JoinPath(root.path(), "mp");
  ASSERT_THAT(mkdir(src.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(mount_root.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(mount_point.c_str(), 0755), SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(dir, "f")));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(mount_root.c_str(), mount_point.c_str(), nullptr, MS_BIND,
                      nullptr) == 0);

    int dirfd = open(JoinPath(mount_point, "b").c_str(),
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    TEST_PCHECK(dirfd >= 0);
    TEST_PCHECK(rename(dir.c_str(), moved_dir.c_str()) == 0);

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, mount_root,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(ClassifyFs(openat(dirfd, "f", O_RDONLY)));
  }));
  const int want = LandlockErratumFixed(3) ? kAllowed : kDenied;
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == want)
      << "exit status " << status;
}

TEST(LandlockV1Test, MagicLinkReopenCannotWidenAccess) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string allowed;
  allowed = dir.path();
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_READ_FILE);
    int fd = open(target.c_str(), O_RDONLY);
    if (fd < 0) {
      _exit(kSetup);
    }
    const std::string proc_path = "/proc/self/fd/" + std::to_string(fd);
    int ro = open(proc_path.c_str(), O_RDONLY);
    if (ro < 0) {
      _exit(kOther);
    }
    close(ro);
    _exit(ClassifyFs(open(proc_path.c_str(), O_RDWR)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnhandledOpenModesRemainAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  static std::string allowed;
  allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    // WRITE_FILE is not handled, so a write-only open is unrestricted.
    int wo = open(target.c_str(), O_WRONLY);
    if (wo < 0) {
      _exit(ClassifyFs(wo));
    }
    close(wo);
    // A read-write open still requires the handled READ_FILE right.
    _exit(ClassifyFs(open(target.c_str(), O_RDWR)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, OpenCreatOnExistingFileDoesNotRequireMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath existing =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string allowed;
  allowed = dir.path();
  static std::string existing_path;
  existing_path = existing.path();
  static std::string missing_path;
  missing_path = JoinPath(dir.path(), "newfile");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_WRITE_FILE);
    // O_CREAT on an existing file creates nothing, so MAKE_REG is not
    // required.
    int fd = open(existing_path.c_str(), O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
      _exit(ClassifyFs(fd));
    }
    close(fd);
    // Actually creating a file still requires MAKE_REG.
    _exit(ClassifyFs(open(missing_path.c_str(), O_CREAT | O_WRONLY, 0644)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, OpenCreatOnExistingFileStillRequiresOpenRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath existing =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string allowed;
  allowed = dir.path();
  static std::string existing_path;
  existing_path = existing.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyFs(open(existing_path.c_str(), O_CREAT | O_WRONLY, 0644)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, TruncateUnrestrictedByV1Domain) {
  SKIP_IF(LandlockAbiVersion() < 1);

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "content", 0666));
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open(target.c_str(), O_WRONLY);
    if (fd < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    // LANDLOCK_ACCESS_FS_TRUNCATE is ABI v3; a v1 domain cannot restrict
    // truncation, even when it denies WRITE_FILE.
    if (truncate(target.c_str(), 3) != 0) {
      _exit(errno == EACCES ? kDenied : kOther);
    }
    if (ftruncate(fd, 0) != 0) {
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RulesInOneLayerUnionAcrossAncestry) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent_dir.path()));
  TempPath child_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(child_dir.path()));
  TempPath parent_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(parent_dir.path()));
  static std::string parent;
  parent = parent_dir.path();
  static std::string child;
  child = child_dir.path();
  static std::string in_child;
  in_child = child_file.path();
  static std::string in_parent;
  in_parent = parent_file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                           LANDLOCK_ACCESS_FS_WRITE_FILE);
    AddPathRule(fd, parent, LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(fd, child, LANDLOCK_ACCESS_FS_WRITE_FILE);
    EnforceOrDie(fd);
    // Within one layer, rules encountered along the ancestry walk are
    // unioned: READ_FILE from the parent rule plus WRITE_FILE from the
    // child rule satisfy a read-write open below the child.
    int rw = open(in_child.c_str(), O_RDWR);
    if (rw < 0) {
      _exit(ClassifyFs(rw));
    }
    close(rw);
    // Directly below the parent, only READ_FILE has been granted.
    int denied = open(in_parent.c_str(), O_RDWR);
    if (denied >= 0 || errno != EACCES) {
      _exit(kOther);
    }
    _exit(TryReadOpen(in_parent));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RenameExchangeAcrossDirectoriesRefusedWithExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath a_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath b_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath a = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(a_dir.path()));
  TempPath b = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(b_dir.path()));
  static std::string top;
  top = root.path();
  static std::string src;
  src = a.release();
  static std::string dst;
  dst = b.release();
  constexpr uint64_t kRights =
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE;
  constexpr int kExchangeUnsupported = 107;
  auto classify = [](int rc) -> int {
    if (rc == 0) {
      return kAllowed;
    }
    switch (errno) {
      case EACCES:
        return kErrAcces;
      case EXDEV:
        return kErrExdev;
      case EINVAL:
      case ENOSYS:
        return kExchangeUnsupported;
      default:
        return kOther;
    }
  };

  // With every needed make/remove right granted, a cross-directory exchange
  // is still refused with EXDEV because no v1 layer can allow reparenting.
  int granted = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, top, kRights);
    _exit(classify(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(),
                             RENAME_EXCHANGE)));
  }));
  SKIP_IF(WIFEXITED(granted) && WEXITSTATUS(granted) == kExchangeUnsupported);
  EXPECT_TRUE(WIFEXITED(granted) && WEXITSTATUS(granted) == kErrExdev)
      << "exit status " << granted;

  // EACCES takes priority over EXDEV when a needed right is missing.
  int denied = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kRights, top, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(classify(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD, dst.c_str(),
                             RENAME_EXCHANGE)));
  }));
  EXPECT_TRUE(WIFEXITED(denied) && WEXITSTATUS(denied) == kErrAcces)
      << "exit status " << denied;
}

TEST(LandlockV1Test, RuleAboveBindMountPointReachesMountContents) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string src = JoinPath(root.path(), "src");
  const std::string covering = JoinPath(root.path(), "covering");
  const std::string mount_point = JoinPath(covering, "mp");
  ASSERT_THAT(mkdir(src.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(covering.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(mount_point.c_str(), 0755), SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(src, "f")));
  const std::string via_mount = JoinPath(mount_point, "f");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(src.c_str(), mount_point.c_str(), nullptr, MS_BIND,
                      nullptr) == 0);

    // The rule is on an ancestor of the mount point, not on the bind
    // source: the ancestry walk must cross the mount boundary upwards.
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, covering,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(via_mount));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, AddRuleNullAttrReturnsEfault) {
  SKIP_IF(LandlockAbiVersion() < 1);

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());
  EXPECT_THAT(
      landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, nullptr, 0),
      SyscallFailsWithErrno(EFAULT));
  close(ruleset_fd);
}

TEST(LandlockV1Test, FileRuleAcceptsOnlyFileCompatibleRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  int file_fd = open(file.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(file_fd, SyscallSucceeds());

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = kFsAccessV1;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());

  constexpr uint64_t kFileCompatible = LANDLOCK_ACCESS_FS_EXECUTE |
                                       LANDLOCK_ACCESS_FS_WRITE_FILE |
                                       LANDLOCK_ACCESS_FS_READ_FILE;
  for (int bit = 0; bit < 13; bit++) {
    const uint64_t access = 1ULL << bit;
    landlock_path_beneath_attr path_beneath = {};
    path_beneath.allowed_access = access;
    path_beneath.parent_fd = file_fd;
    if (access & kFileCompatible) {
      EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                    &path_beneath, 0),
                  SyscallSucceeds())
          << "access bit " << bit;
    } else {
      EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                    &path_beneath, 0),
                  SyscallFailsWithErrno(EINVAL))
          << "access bit " << bit;
    }
  }
  close(ruleset_fd);
  close(file_fd);
}

TEST(LandlockV1Test, RelativePathsAreEnforced) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed_abs = JoinPath(root.path(), "a");
  const std::string outside_abs = JoinPath(root.path(), "b");
  ASSERT_THAT(mkdir(allowed_abs.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(outside_abs.c_str(), 0755), SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(allowed_abs, "f")));
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(outside_abs, "g")));
  static std::string top;
  top = root.path();
  static std::string allowed;
  allowed = allowed_abs;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (chdir(top.c_str()) != 0) {
      _exit(kSetup);
    }
    int outside_dirfd = open("b", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (outside_dirfd < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen("a/f") != kAllowed) {
      _exit(kOther);
    }
    int denied = open("b/g", O_RDONLY);
    if (denied >= 0 || errno != EACCES) {
      _exit(kOther);
    }
    // Lookups starting from a directory fd are restricted all the same.
    _exit(ClassifyFs(openat(outside_dirfd, "g", O_RDONLY)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, PreEnforcementFdsKeepWorking) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open(target.c_str(), O_RDWR);
    if (fd < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    // Landlock checks accesses at open time only; fds opened before
    // enforcement retain their access.
    if (pwrite(fd, "x", 1, 0) != 1) {
      _exit(kOther);
    }
    char c;
    if (pread(fd, &c, 1, 0) != 1 || c != 'x') {
      _exit(kOther);
    }
    // A fresh open of the same file is denied.
    _exit(TryReadOpen(target) == kDenied ? kAllowed : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, SameRulesetEnforcedTwiceStillDenies) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  static std::string allowed;
  allowed = allowed_dir.path();
  static std::string in_allowed;
  in_allowed = inside.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(fd, allowed, LANDLOCK_ACCESS_FS_READ_FILE);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    // The same ruleset fd may be enforced repeatedly, stacking identical
    // layers.
    if (landlock_restrict_self(fd, 0) != 0 ||
        landlock_restrict_self(fd, 0) != 0) {
      _exit(kSetup);
    }
    close(fd);
    if (TryReadOpen(in_allowed) != kAllowed) {
      _exit(kOther);
    }
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ProcEnvironOfUnsandboxedTargetDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  static std::string environ_path;
  environ_path = "/proc/" + std::to_string(getpid()) + "/environ";

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open(environ_path.c_str(), O_RDONLY);
    if (fd < 0) {
      _exit(kSetup);
    }
    char c;
    _exit(read(fd, &c, 1) >= 0 ? kAllowed : kSetup);
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kAllowed));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // Handling an access unrelated to reads keeps path lookups
    // unrestricted, isolating the ptrace-scoping check, as in the kernel's
    // ptrace selftests.
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_BLOCK);
    int fd = open(environ_path.c_str(), O_RDONLY);
    if (fd < 0) {
      _exit(errno == EACCES ? kDenied : kOther);
    }
    char c;
    ssize_t n = read(fd, &c, 1);
    if (n < 0 && errno == EACCES) {
      _exit(kDenied);
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExecuteInsideAllowedTreeDeniedWithoutExecuteGrant) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(allowed_dir.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
                  allowed, LANDLOCK_ACCESS_FS_READ_FILE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

constexpr int kEperm = 104;

int ClassifyMount(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  return errno == EPERM ? kEperm : kOther;
}

#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif

int PivotRoot(const std::string& new_root, const std::string& put_old) {
  return syscall(SYS_pivot_root, new_root.c_str(), put_old.c_str());
}

int MoveMount(int from_dirfd, const std::string& from, int to_dirfd,
              const std::string& to, uint32_t flags) {
  return syscall(SYS_move_mount, from_dirfd, from.c_str(), to_dirfd,
                 to.c_str(), flags);
}

TEST(LandlockV1Test, MountDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = src_dir.path();
  const std::string to = dst_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(from.c_str(), to.c_str(), nullptr, MS_BIND, nullptr) ==
                0);
    TEST_PCHECK(umount2(to.c_str(), MNT_DETACH) == 0);

    ApplyFsPolicy(kFsAccessV1, from, kFsAccessV1);
    _exit(ClassifyMount(
        mount(from.c_str(), to.c_str(), nullptr, MS_BIND, nullptr)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}

TEST(LandlockV1Test, Umount2DeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = src_dir.path();
  const std::string to = dst_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(from.c_str(), to.c_str(), nullptr, MS_BIND, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, to, kFsAccessV1);
    _exit(ClassifyMount(umount2(to.c_str(), MNT_DETACH)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}

TEST(LandlockV1Test, PivotRootDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath new_root_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string new_root = new_root_dir.path();
  const std::string put_old = JoinPath(new_root, "old");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("none", new_root.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(put_old.c_str(), 0755) == 0);

    ApplyFsPolicy(kFsAccessV1, new_root, kFsAccessV1);
    _exit(ClassifyMount(PivotRoot(new_root, put_old)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}

TEST(LandlockV1Test, MoveMountDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  MoveMount(-1, "", -1, "", 0);
  SKIP_IF(errno == ENOSYS);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath first_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath second_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = src_dir.path();
  const std::string first = first_dir.path();
  const std::string second = second_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(from.c_str(), first.c_str(), nullptr, MS_BIND,
                      nullptr) == 0);

    ApplyFsPolicy(kFsAccessV1, from, kFsAccessV1);
    _exit(ClassifyMount(MoveMount(AT_FDCWD, first, AT_FDCWD, second, 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}


TEST(LandlockV1Test, MountWithMissingTargetReportsEnoentNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = src_dir.path();
  const std::string missing = JoinPath(root.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, from, kFsAccessV1);
    _exit(ClassifyErrno(
        mount(from.c_str(), missing.c_str(), nullptr, MS_BIND, nullptr)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, Umount2OfNonMountpointReportsEinvalNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath plain_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string plain = plain_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, plain, kFsAccessV1);
    _exit(ClassifyErrno(umount2(plain.c_str(), MNT_DETACH)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrInval)
      << "exit status " << status;
}

TEST(LandlockV1Test, PivotRootWithMissingNewRootReportsEnoentNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir = root.path();
  const std::string missing = JoinPath(dir, "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, dir, kFsAccessV1);
    _exit(ClassifyErrno(PivotRoot(missing, dir)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

// Linux resolves both pivot_root paths with LOOKUP_DIRECTORY before the
// Landlock hook, so a non-directory new_root reports ENOTDIR, not EPERM.
TEST(LandlockV1Test, PivotRootWithNonDirectoryNewRootReportsEnotdirNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir = root.path();
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir));
  const std::string nondir = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, dir, kFsAccessV1);
    _exit(ClassifyErrno(PivotRoot(nondir, dir)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNotdir)
      << "exit status " << status;
}

// Linux resolves move_mount's source path before its target path, so when
// both are bad the source's errno wins even for a landlocked caller.
TEST(LandlockV1Test, MoveMountResolvesSourceBeforeTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  MoveMount(-1, "", -1, "", 0);
  SKIP_IF(errno == ENOSYS);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string bad_source = JoinPath(file.path(), "x");     // ENOTDIR
  const std::string missing_target = JoinPath(root.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, root.path(), kFsAccessV1);
    _exit(ClassifyErrno(
        MoveMount(AT_FDCWD, bad_source, AT_FDCWD, missing_target, 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNotdir)
      << "exit status " << status;
}

TEST(LandlockV1Test, MoveMountWithMissingSourceReportsEnoentNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  MoveMount(-1, "", -1, "", 0);
  SKIP_IF(errno == ENOSYS);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string to = dst_dir.path();
  const std::string missing = JoinPath(root.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, to, kFsAccessV1);
    _exit(ClassifyErrno(MoveMount(AT_FDCWD, missing, AT_FDCWD, to, 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayCopyUpAllowedByRuleOnMergedDir) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string source = JoinPath(lower, "victim");
  const std::string target = JoinPath(merged, "victim");
  const std::string data =
      "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(lower.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(upper.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(work.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(merged.c_str(), 0777) == 0);

    int lower_fd = open(source.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    TEST_PCHECK(lower_fd >= 0);
    TEST_PCHECK(close(lower_fd) == 0);

    if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
      _exit(kSetup);
    }

    ApplyFsPolicy(kFsAccessV1, merged, kFsAccessV1);
    _exit(ClassifyFs(open(target.c_str(), O_WRONLY)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayRuleOnLowerFileSurvivesCopyUp) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string source = JoinPath(lower, "victim");
  const std::string target = JoinPath(merged, "victim");
  const std::string data =
      "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(lower.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(upper.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(work.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(merged.c_str(), 0777) == 0);

    int lower_fd = open(source.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    TEST_PCHECK(lower_fd >= 0);
    TEST_PCHECK(close(lower_fd) == 0);

    if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
      _exit(kSetup);
    }

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  target,
                  LANDLOCK_ACCESS_FS_READ_FILE |
                      LANDLOCK_ACCESS_FS_WRITE_FILE);

    int writable = open(target.c_str(), O_WRONLY);
    if (writable < 0) {
      _exit(ClassifyFs(writable));
    }
    TEST_PCHECK(close(writable) == 0);

    _exit(ClassifyFs(open(target.c_str(), O_RDONLY)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayUnlinkOfMissingFileReportsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string missing_file = JoinPath(merged, "missing");
  const std::string missing_dir = JoinPath(merged, "missing_dir");
  const std::string data =
      "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(lower.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(upper.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(work.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(merged.c_str(), 0777) == 0);
    if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
      _exit(kSetup);
    }

    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE |
                            LANDLOCK_ACCESS_FS_REMOVE_DIR);
    int rc = ClassifyErrno(unlink(missing_file.c_str()));
    if (rc != kErrNoent) {
      _exit(rc);
    }
    _exit(ClassifyErrno(rmdir(missing_dir.c_str())));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}


constexpr int kRaceIterations = 300;

void MakeRaceDirs(const std::string& root, std::string* covered,
                  std::string* uncovered, std::string* swap_dir,
                  std::string* link) {
  *covered = JoinPath(root, "covered");
  *uncovered = JoinPath(root, "uncovered");
  *swap_dir = JoinPath(root, "swap");
  *link = JoinPath(*swap_dir, "link");
  ASSERT_THAT(mkdir(covered->c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(mkdir(uncovered->c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(mkdir(swap_dir->c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(symlink(covered->c_str(), link->c_str()), SyscallSucceeds());
}

void SwapLinkUntilStopped(const std::string& link, const std::string& covered,
                          const std::string& uncovered,
                          std::atomic<bool>* stop) {
  const std::string tmp = link + ".tmp";
  bool to_covered = false;
  while (!stop->load(std::memory_order_relaxed)) {
    unlink(tmp.c_str());
    if (symlink(to_covered ? covered.c_str() : uncovered.c_str(),
                tmp.c_str()) != 0) {
      continue;
    }
    if (rename(tmp.c_str(), link.c_str()) != 0) {
      continue;
    }
    to_covered = !to_covered;
  }
}

void RemoveSwapLinks(const std::string& link) {
  EXPECT_THAT(unlink(link.c_str()), SyscallSucceeds());
  unlink((link + ".tmp").c_str());
}

TEST(LandlockV1Test, CreateThroughSwappedSymlinkStaysUnderRule) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const DisableSave ds;

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string covered, uncovered, swap_dir, link;
  ASSERT_NO_FATAL_FAILURE(
      MakeRaceDirs(base.path(), &covered, &uncovered, &swap_dir, &link));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kFsAccessV1);
    AddPathRule(fd, covered,
                LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_WRITE_FILE);
    AddPathRule(fd, uncovered, LANDLOCK_ACCESS_FS_WRITE_FILE);
    AddPathRule(fd, swap_dir,
                LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REMOVE_FILE);
    EnforceOrDie(fd);

    std::atomic<bool> stop(false);
    ScopedThread swapper(
        [&] { SwapLinkUntilStopped(link, covered, uncovered, &stop); });

    int created = 0;
    for (int i = 0; i < kRaceIterations; i++) {
      const std::string victim = JoinPath(link, "victim." + std::to_string(i));
      int victim_fd =
          open(victim.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
      if (victim_fd >= 0) {
        created++;
        close(victim_fd);
      }
    }
    stop.store(true, std::memory_order_relaxed);
    swapper.Join();

    _exit(created > 0 ? kAllowed : kSetup);
  }));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;

  EXPECT_THAT(ASSERT_NO_ERRNO_AND_VALUE(ListDir(uncovered, true)),
              ::testing::IsEmpty());
  RemoveSwapLinks(link);
}

TEST(LandlockV1Test, UnlinkThroughSwappedSymlinkStaysUnderRule) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const DisableSave ds;

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string covered, uncovered, swap_dir, link;
  ASSERT_NO_FATAL_FAILURE(
      MakeRaceDirs(base.path(), &covered, &uncovered, &swap_dir, &link));

  for (int i = 0; i < kRaceIterations; i++) {
    const std::string name = "victim." + std::to_string(i);
    ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(covered, name)));
    ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(uncovered, name)));
  }

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kFsAccessV1);
    AddPathRule(fd, covered, LANDLOCK_ACCESS_FS_REMOVE_FILE);
    AddPathRule(fd, swap_dir,
                LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REMOVE_FILE);
    EnforceOrDie(fd);

    std::atomic<bool> stop(false);
    ScopedThread swapper(
        [&] { SwapLinkUntilStopped(link, covered, uncovered, &stop); });

    int removed = 0;
    for (int i = 0; i < kRaceIterations; i++) {
      const std::string victim = JoinPath(link, "victim." + std::to_string(i));
      if (unlink(victim.c_str()) == 0) {
        removed++;
      }
    }
    stop.store(true, std::memory_order_relaxed);
    swapper.Join();

    _exit(removed > 0 ? kAllowed : kSetup);
  }));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;

  EXPECT_THAT(ASSERT_NO_ERRNO_AND_VALUE(ListDir(uncovered, true)),
              ::testing::SizeIs(kRaceIterations));
  RemoveSwapLinks(link);
}


TEST(LandlockV1Test, PipeIsReopenableThroughProcFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fds[2];
    if (pipe(fds) != 0) {
      _exit(kSetup);
    }
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(TryReadOpen("/proc/self/fd/" + std::to_string(fds[0])));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, MemfdIsReopenableThroughProcFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int memfd = syscall(__NR_memfd_create, "landlock-test", 0);
    if (memfd < 0) {
      _exit(kSetup);
    }
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(TryReadOpen("/proc/self/fd/" + std::to_string(memfd)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, NamespaceFileIsOpenableUnderDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(TryReadOpen("/proc/self/ns/net"));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, SocketProcFdIsNotDeniedByLandlock) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
      _exit(kSetup);
    }
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    const std::string path = "/proc/self/fd/" + std::to_string(sock);
    int fd = open(path.c_str(), O_RDONLY);
    if (fd >= 0) {
      close(fd);
      _exit(kAllowed);
    }
    _exit(errno == EACCES ? kDenied : kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, MqOpenDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const std::string name = "/landlock_mq_open_denied";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  ASSERT_THAT(mq_close(queue), SyscallSucceeds());
  auto cleanup = Cleanup([&] { EXPECT_THAT(mq_unlink(name.c_str()),
                                           SyscallSucceeds()); });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(ClassifyFs(mq_open(name.c_str(), O_RDWR)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, MqOpenAllowedWhenRightsUnhandled) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const std::string name = "/landlock_mq_open_unhandled";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  ASSERT_THAT(mq_close(queue), SyscallSucceeds());
  auto cleanup = Cleanup([&] { EXPECT_THAT(mq_unlink(name.c_str()),
                                           SyscallSucceeds()); });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    mqd_t fd = mq_open(name.c_str(), O_RDWR);
    if (fd == static_cast<mqd_t>(-1)) {
      _exit(ClassifyFs(-1));
    }
    mq_close(fd);
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, MqOpenAllowedByRuleOnMqueueMount) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string mountpoint = dir.path();
  const std::string name = "/landlock_mq_open_allowed";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  ASSERT_THAT(mq_close(queue), SyscallSucceeds());
  auto cleanup = Cleanup([&] { EXPECT_THAT(mq_unlink(name.c_str()),
                                           SyscallSucceeds()); });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    if (mount("mqueue", mountpoint.c_str(), "mqueue", 0, nullptr) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  mountpoint,
                  LANDLOCK_ACCESS_FS_READ_FILE |
                      LANDLOCK_ACCESS_FS_WRITE_FILE);
    mqd_t fd = mq_open(name.c_str(), O_RDWR);
    if (fd == static_cast<mqd_t>(-1)) {
      _exit(ClassifyFs(-1));
    }
    mq_close(fd);
    _exit(kAllowed);
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

#ifndef SYS_fsopen
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#endif

#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE 0x6
#define FSCONFIG_CMD_RECONFIGURE 0x7
#endif

TEST(LandlockV1Test, FsconfigReconfigureDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fs_fd = syscall(SYS_fsopen, "tmpfs", 0);
    if (fs_fd < 0) {
      _exit(kSetup);
    }
    if (syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_CREATE, nullptr, nullptr,
                0) != 0) {
      _exit(kSetup);
    }
    int mount_fd = syscall(SYS_fsmount, fs_fd, 0, 0);
    if (mount_fd < 0) {
      _exit(kSetup);
    }

    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));

    _exit(ClassifyMount(syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_RECONFIGURE,
                                nullptr, nullptr, 0)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}


pid_t ForkTracee(bool extra_layer, int* stop_fd) {
  int stop[2], ready[2];
  if (pipe(stop) != 0 || pipe(ready) != 0) {
    _exit(kSetup);
  }
  pid_t pid = fork();
  if (pid < 0) {
    _exit(kSetup);
  }
  if (pid == 0) {
    close(stop[1]);
    close(ready[0]);
    if (extra_layer) {
      EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_REG));
    }
    close(ready[1]);
    char c;
    while (read(stop[0], &c, 1) == -1 && errno == EINTR) {
    }
    _exit(0);
  }
  close(stop[0]);
  close(ready[1]);
  char c;
  while (read(ready[0], &c, 1) == -1 && errno == EINTR) {
  }
  close(ready[0]);
  *stop_fd = stop[1];
  return pid;
}

ChildResult TryAttach(pid_t tracee, int stop_fd) {
  int rc = ptrace(PTRACE_ATTACH, tracee, nullptr, nullptr);
  int err = errno;
  if (rc == 0) {
    waitpid(tracee, nullptr, 0);
    ptrace(PTRACE_DETACH, tracee, nullptr, nullptr);
  }
  close(stop_fd);
  waitpid(tracee, nullptr, 0);
  if (rc == 0) {
    return kAllowed;
  }
  return err == EPERM ? kDenied : kOther;
}

TEST(LandlockV1Test, PtraceAttachDeniedForUnsandboxedTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int stop_fd;
    pid_t tracee = ForkTracee(false, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, PtraceAttachAllowedWithinSameDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    int stop_fd;
    pid_t tracee = ForkTracee(false, &stop_fd);
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, PtraceAttachAllowedForMoreRestrictedTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    int stop_fd;
    pid_t tracee = ForkTracee(true, &stop_fd);
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ProcMemOfUnsandboxedTargetIsInaccessible) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int stop_fd;
    pid_t tracee = ForkTracee(false, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));

    const std::string path = "/proc/" + std::to_string(tracee) + "/mem";
    ChildResult result = TryReadOpen(path);
    close(stop_fd);
    waitpid(tracee, nullptr, 0);
    _exit(result);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, PtraceTracemeDeniedWhenParentMoreRestricted) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int go[2], result[2];
    if (pipe(go) != 0 || pipe(result) != 0) {
      _exit(kSetup);
    }
    pid_t child = fork();
    if (child < 0) {
      _exit(kSetup);
    }
    if (child == 0) {
      close(go[1]);
      close(result[0]);
      char c;
      while (read(go[0], &c, 1) == -1 && errno == EINTR) {
      }
      int rc = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
      char out = rc == 0 ? kAllowed : (errno == EPERM ? kDenied : kOther);
      write(result[1], &out, 1);
      _exit(0);
    }
    close(go[0]);
    close(result[1]);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    close(go[1]);

    char out = kOther;
    if (read(result[0], &out, 1) != 1) {
      out = kSetup;
    }
    waitpid(child, nullptr, 0);
    _exit(out);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, DomainEnforcedAfterExecve) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(access("/bin/sh", X_OK) != 0);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath control_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  const TempPath enforced_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string control_cmd;
  control_cmd = "echo x > " + control_file.path();
  static std::string enforced_cmd;
  enforced_cmd = "echo x > " + enforced_file.path();
  static std::string enforced_target;
  enforced_target = enforced_file.path();

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    execl("/bin/sh", "sh", "-c", control_cmd.c_str(),
          static_cast<char*>(nullptr));
    _exit(kSetup);
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == 0));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                           LANDLOCK_ACCESS_FS_WRITE_FILE |
                           LANDLOCK_ACCESS_FS_EXECUTE);
    AddPathRule(fd, "/",
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE);
    EnforceOrDie(fd);
    execl("/bin/sh", "sh", "-c", enforced_cmd.c_str(),
          static_cast<char*>(nullptr));
    _exit(kSetup);
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_NE(WEXITSTATUS(status), 0) << "the redirect was not denied";
  EXPECT_NE(WEXITSTATUS(status), kSetup) << "execve itself failed";
  struct stat st;
  ASSERT_THAT(stat(enforced_target.c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_size, 0);
}

TEST(LandlockV1Test, DomainSurvivesSetuid) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn("/tmp"));
  static std::string target;
  target = file.path();
  constexpr uid_t kNobody = 65534;

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (setuid(kNobody) != 0 || getuid() != kNobody) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kAllowed));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    if (setuid(kNobody) != 0 || getuid() != kNobody) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictSelfAppliesOnlyToCallingThread) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    std::atomic<int> thread_result{kOther};
    {
      ScopedThread t([&thread_result] {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
          thread_result = kSetup;
          return;
        }
        int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
        if (landlock_restrict_self(fd, 0) != 0) {
          thread_result = kSetup;
          return;
        }
        close(fd);
        thread_result = TryReadOpen(target);
      });
      t.Join();
    }
    if (thread_result == kSetup) {
      _exit(kSetup);
    }
    if (thread_result != kDenied) {
      _exit(kOther);
    }
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ThreadInheritsDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    std::atomic<int> thread_result{kOther};
    {
      ScopedThread t([&thread_result] { thread_result = TryReadOpen(target); });
      t.Join();
    }
    _exit(thread_result);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ChildRestrictionDoesNotAffectParent) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    pid_t pid = fork();
    if (pid < 0) {
      _exit(kSetup);
    }
    if (pid == 0) {
      ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
      _exit(TryReadOpen(target));
    }
    int st;
    if (waitpid(pid, &st, 0) < 0 ||
        !(WIFEXITED(st) && WEXITSTATUS(st) == kDenied)) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, PtraceAttachDeniedBetweenSiblingDomains) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int stop_fd;
    pid_t tracee = ForkTracee(true, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, PtraceTracemeAllowedWithinSameDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    int result[2];
    if (pipe(result) != 0) {
      _exit(kSetup);
    }
    pid_t child = fork();
    if (child < 0) {
      _exit(kSetup);
    }
    if (child == 0) {
      close(result[0]);
      int rc = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
      char out = rc == 0 ? kAllowed : (errno == EPERM ? kDenied : kOther);
      write(result[1], &out, 1);
      _exit(0);
    }
    close(result[1]);
    char out = kOther;
    if (read(result[0], &out, 1) != 1) {
      out = kSetup;
    }
    waitpid(child, nullptr, 0);
    _exit(out);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ProcessVmReadvDeniedForUnsandboxedTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  static char remote_buf[8] = "watched";
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int stop_fd;
    pid_t tracee = ForkTracee(false, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));

    char local_buf[sizeof(remote_buf)] = {};
    struct iovec local = {local_buf, sizeof(local_buf)};
    struct iovec remote = {remote_buf, sizeof(remote_buf)};
    ssize_t n = process_vm_readv(tracee, &local, 1, &remote, 1, 0);
    int err = errno;
    ChildResult res =
        n >= 0 ? kAllowed
               : ((err == EPERM || err == EACCES) ? kDenied : kOther);
    close(stop_fd);
    waitpid(tracee, nullptr, 0);
    _exit(res);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
