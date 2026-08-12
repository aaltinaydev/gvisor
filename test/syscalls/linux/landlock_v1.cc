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

// To an implementation whose highest ABI is 1 the attr ends at
// handled_access_fs, and any nonzero byte past those 8 bytes is an unknown
// tail reported as E2BIG, even where a later ABI put handled_access_net.
// Kernels that know the field reject its unknown bits as EINVAL before an
// all-empty request is reported; ENOMSG is wrong everywhere.
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

// Size handling of the attr follows copy_min_struct_from_user(): a struct
// shorter than 8 bytes cannot even hold handled_access_fs, one of exactly 8
// bytes is accepted with the missing fields read as zero, one longer than a
// page is refused outright, and unknown trailing bytes are only tolerated if
// zero.
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
  // A struct longer than the implementation knows, with a nonzero byte in the
  // tail. Kernels that know more of the tail as real fields report the
  // garbage as EINVAL instead; ENOMSG or success would be wrong everywhere.
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
  // To ABI 1 the struct ends at handled_access_fs; a nonzero byte anywhere
  // past offset 8 is tail garbage, E2BIG, even at offsets a later ABI turned
  // into handled_access_net or scoped. Such kernels report EINVAL for their
  // known fields' unknown bits instead.
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

// The ruleset fd is resolved before the rule type is looked at, as
// sys_landlock_add_rule() resolves the fd before the switch on rule_type, so a
// call that gets both wrong is told about the fd.
TEST(LandlockV1Test, AddRuleBadFdWithBadRuleTypeReportsBadFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_path_beneath_attr path_beneath = {};
  EXPECT_THAT(landlock_add_rule(-1, static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EBADF));

  // A valid fd that is not a ruleset is still reported before the rule type.
  int file_fd = open("/", O_RDONLY | O_CLOEXEC);
  ASSERT_THAT(file_fd, SyscallSucceeds());
  EXPECT_THAT(landlock_add_rule(file_fd,
                                static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EBADFD));
  close(file_fd);
}

// An empty allowed_access is reported before the parent fd is even looked at,
// as add_rule_path_beneath() orders them.
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

// Nonzero flags are EINVAL. Bit 0 is LANDLOCK_ADD_RULE_QUIET on later ABIs
// and succeeds there, so the probe uses bit 1, unknown everywhere.
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

// A rule on a non-directory may only carry rights a file can satisfy;
// granting a directory-only right like READ_DIR on a regular file is EINVAL,
// per landlock_append_fs_rule()'s ACCESS_FILE masking.
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
  // A file-compatible right on the same file is accepted.
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallSucceeds());
  close(parent_fd);
  close(fd);
}

// The ruleset fd supports none of the ordinary file operations.
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

// A rule can only name a file that lives on a mount the application can reach
// through the mount tree. Files on the kernel's own mounts — the tmpfs behind
// memfd_create(2), nsfs, pipefs, sockfs — are rejected, since a rule naming one
// could never match anything.
//
// Matches Linux [security/landlock/syscalls.c]:get_path_from_fd()
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

// Files on kernel-internal mounts are exempt from the policy, not just barred
// from rules: no rule could ever name them, so denying them would only make
// reopening a descriptor the thread already holds impossible under any domain.
// Linux allows them via SB_NOUSER/MNT_INTERNAL in is_nouser_or_private().
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

// Under gVisor, descriptors donated by the runtime — the application's stdio
// among them — live on the internal host mount, so they take the same
// exemption: a fully restrictive domain must not break reopening stderr, and
// a rule can no more name one than it can name a pipe.
TEST(LandlockV1Test, HostFdsAreInternal) {
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  // Control: without a domain, stderr must be reopenable through
  // /proc/self/fd, or the run below proves nothing.
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

// The no_new_privs check comes before any check on what the caller passed, so a
// thread that may not sandbox itself is told that and not that its arguments
// are bad. See Linux commit eba39ca4b155 ("landlock: Change
// landlock_restrict_self(2) check ordering").
TEST(LandlockV1Test, RestrictSelfWithoutNoNewPrivsReportsEpermNotEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  AutoCapability cap_admin(CAP_SYS_ADMIN, false);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // Both the flags and the descriptor are invalid, and neither is what the
    // call fails on.
    _exit(landlock_restrict_self(-1, ~0u) < 0 && errno == EPERM ? kDenied
                                                                : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// Once no_new_privs is satisfied, unknown flags are EINVAL. Later ABIs accept
// their LOG_* and TSYNC bits in the low positions, so the probe uses bit 31,
// unknown everywhere. This is the "reject later-ABI flags" behavior the v1
// claim depends on, distinct from the EPERM-ordering test above.
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

// CAP_SYS_ADMIN in the caller's user namespace substitutes for no_new_privs.
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
    // Deliberately no prctl(PR_SET_NO_NEW_PRIVS).
    if (landlock_restrict_self(fd, 0) != 0) {
      _exit(kSetup);
    }
    close(fd);
    // The domain is enforced, proving the call did more than return 0.
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// A domain takes at most LANDLOCK_MAX_NUM_LAYERS (16) stacked rulesets; the
// seventeenth is refused with E2BIG and leaves the sixteen intact.
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

// open(2) accepts a fourth access mode alongside O_RDONLY, O_WRONLY and O_RDWR,
// which yields a file that is neither readable nor writable. Landlock takes the
// rights an open requires from the mode the resulting file has, so this one
// requires none and a domain that grants nothing lets it through.
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

// A Landlock denial is one error among several that a removal can produce, and
// Linux fixes where it sits among them. do_unlinkat() and do_rmdir() call
// mnt_want_write() and resolve the victim before security_path_unlink() and
// security_path_rmdir(), and reach may_delete() and the filesystem's own
// removal only from inside vfs_unlink() and vfs_rmdir(), which run after the
// hook. So EROFS, ENOENT and a trailing slash outrank EACCES, and EACCES in
// turn outranks the sticky-bit EPERM, EISDIR, ENOTDIR and ENOTEMPTY.
//
// Getting this wrong leaks information in both directions: reporting EACCES
// where Linux reports ENOENT tells a sandboxed thread nothing it should not
// know, but reporting ENOTEMPTY where Linux reports EACCES tells it about a
// directory the policy is meant to hide.

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

// Creating over an existing file is EEXIST before it is the policy's EACCES:
// filename_create() resolves the child before security_path_mkdir() and its
// siblings run.
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

// O_PATH opens no file content, so hook_file_open() requests nothing and even
// a deny-everything domain permits it.
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

// A denied open must fail before O_TRUNC takes effect: the check runs before
// the truncation in every implementation, so the file's contents survive.
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

// Each mknod type demands its own MAKE_* right; granting one does not grant
// the others.
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

// Binding a unix socket to a filesystem path creates a socket file, which
// needs MAKE_SOCK in the directory, through the same mknod hook.
TEST(LandlockV1Test, UnixBindRequiresMakeSock) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string allowed;
  allowed = dir.path();

  // Binds to a name relative to the working directory, which is set to the
  // covered directory first: an absolute TEST_TMPDIR path can exceed
  // sun_path, and the cwd is resolved like any other path prefix.
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

// Rules for the same file in different layers intersect: every layer must
// grant a right on its own, so a second layer granting only WRITE on a file
// the first layer granted only READ leaves both denied.
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
    // READ is now denied by the second layer, WRITE by the first.
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

// filename_unlinkat() rejects a trailing slash before the hook, with the
// comment "Why not before? Because we want correct error value".
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

// unlink(2) acts on the covered dentry, not on what is mounted over it:
// do_unlinkat()'s __lookup_hash() does not follow mounts, so the trailing
// slash reports the mount point directory's EISDIR, with or without a domain.
// A resolution that followed the mount would instead restart in the mounted
// filesystem with no path left and misreport ENOENT.
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
    // Without a domain first, so a failure below is an ordering bug and not
    // Landlock misapplied.
    TEST_PCHECK(unlink(target.c_str()) < 0 && errno == EISDIR);
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

// The same trailing-slash-before-the-hook ordering on a kernfs filesystem,
// where the victim walk reports ENOTDIR itself and only EISDIR is left for
// the explicit check.
TEST(LandlockV1Test, UnlinkKernfsTrailingSlashReportsEisdirNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink("/proc/sys/")));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

// link(2) with a directory source is EPERM from vfs_link(), which do_linkat()
// reaches only after security_path_link(), so with a domain active the
// cross-directory EXDEV wins on every filesystem, kernfs included.
TEST(LandlockV1Test, LinkOfProcDirectoryUnderDomainIsExdevNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);

  // Without a domain the directory source is EPERM.
  EXPECT_THAT(link("/proc/self/task", "/proc/landlock_test_link"),
              SyscallFailsWithErrno(EPERM));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyErrno(link("/proc/self/task", "/proc/landlock_test_link")));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrExdev)
      << "exit status " << status;
}

// may_delete() is what turns unlink(2) of a directory into EISDIR, and it runs
// after the hook.
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

// ENOTEMPTY comes from the filesystem's own ->rmdir(), which vfs_rmdir() calls
// after the hook. Reporting it would tell the sandboxed thread that a directory
// it may not remove is not empty.
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

// The sticky bit's EPERM comes from __check_sticky(), reached through
// may_delete() inside vfs_unlink(), so the hook decides first.
//
// The sticky check exempts the caller when it owns either the victim or the
// directory, or when it has CAP_FOWNER, so the test hands both to another user
// and drops the capability.
TEST(LandlockV1Test, UnlinkInStickyDirReportsEaccesNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_FOWNER)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_CHOWN)));

  const TempPath sticky_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(sticky_dir.path()));
  ASSERT_THAT(chmod(sticky_dir.path().c_str(), 01777), SyscallSucceeds());
  // Any uid other than the caller's will do; nobody is conventional.
  constexpr uid_t kNobody = 65534;
  SKIP_IF(chown(victim.path().c_str(), kNobody, kNobody) != 0);
  SKIP_IF(chown(sticky_dir.path().c_str(), kNobody, kNobody) != 0);
  static std::string target;
  target = victim.path();

  // Without a domain, the sticky bit alone denies the unlink with EPERM. This
  // is the control: it establishes that the test really did arrange a sticky
  // denial, so that the EACCES below is the hook winning rather than the
  // sticky check quietly not applying.
  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (!SetCapability(CAP_FOWNER, false).ok()) {
      _exit(kSetup);
    }
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  ASSERT_TRUE(WIFEXITED(control) && WEXITSTATUS(control) == kErrPerm)
      << "control exit status " << control;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (!SetCapability(CAP_FOWNER, false).ok()) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

// mnt_want_write() runs before the hook, so a read-only mount is reported as
// such even when the policy would also have refused.
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

// The same ordering on a kernfs-backed filesystem: creating on a read-only
// proc mount is EROFS before it is the policy's EACCES.
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

// execve(2) opens the file with O_RDONLY, so Linux requires
// LANDLOCK_ACCESS_FS_READ_FILE in addition to LANDLOCK_ACCESS_FS_EXECUTE. A
// policy that handles only READ_FILE therefore still restricts execution, even
// though it does not handle EXECUTE at all.
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

// Granting EXECUTE alone is not enough when the policy also handles READ_FILE:
// both rights are required, and both must be granted beneath the same
// directory.
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

// Conversely, READ_FILE is only required when the policy handles it. A policy
// handling EXECUTE alone must still permit an execve(2) it grants EXECUTE for.
// The exec fails on its missing interpreter rather than succeeding, so anything
// other than EACCES means Landlock allowed it.
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

// EXDEV is not the only answer reparenting can get. current_check_refer_path()
// prioritizes EACCES over EXDEV: if the policy denies a right the operation
// would need even within one directory, that denial is reported, and EXDEV is
// reserved for the case where the only thing missing is the ability to
// reparent. The comment on that function explains why — it lets a caller tell
// "there is no way to do this" apart from "copy the file instead".
//
// Here the destination grants the right to create the file but the source
// grants nothing, so the rename is denied for want of REMOVE_FILE.
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

// The mirror image: the source may remove the file but the destination may not
// create one.
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

// Moving a directory needs MAKE_DIR and REMOVE_DIR rather than the file
// rights, so a policy that grants only the file rights denies it.
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

// link(2) does not detach the source, so the source directory needs no removal
// right and its absence must not turn the EXDEV into an EACCES.
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

// It does need the right to create the file in the destination, though.
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
// The filesystem does not implement RENAME_NOREPLACE and rejects the flag
// outright, so the rename never reaches the point this is testing. rename.cc
// tolerates the same answer.
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

// A same-directory RENAME_EXCHANGE of two regular files needs both MAKE_REG
// and REMOVE_FILE, the union current_check_refer_path() computes for it.
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
  // Filesystems that do not implement RENAME_EXCHANGE report EINVAL, which is
  // treated as unsupported rather than a failure.
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

// do_renameat2() rejects RENAME_NOREPLACE over an existing destination before
// it calls security_path_rename(), so a domain that would otherwise refuse the
// rename must not turn that EEXIST into its own error. Here the refusal would
// be EXDEV, since the two directories differ.
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

// The same ordering holds within one directory, where the refusal would
// otherwise be EACCES.
TEST(LandlockV1Test, RenameNoReplaceOverExistingReportsEexistNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  TempPath dst_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.path();
  const std::string dst = dst_file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    // Handle the rights the rename needs but grant none of them, so that the
    // domain would deny it.
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

// RENAME_NOREPLACE onto a name that does not exist is an ordinary rename, so
// the domain still gets to refuse it.
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

// Everything vfs_rename() checks comes after security_path_rename(), just as it
// does for unlink(2) and rmdir(2) above: filename_renameat2() calls the hook
// last, immediately before vfs_rename(). So the domain's EACCES outranks the
// ENOTEMPTY the filesystem's own ->rename() reports for a non-empty
// destination, which would otherwise tell a sandboxed thread what is inside a
// directory the policy is meant to hide.
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

  // The control establishes that the rename really would fail with ENOTEMPTY:
  // the domain handles a right the rename does not need, so it permits it.
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

// The EISDIR for renaming a non-directory over a directory comes from
// vfs_rename() too, so it loses to the hook as well.
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

// do_linkat() calls may_linkat() — the protected_hardlinks check — before
// security_path_link(), and reaches everything else only from inside
// vfs_link(), after it. So the EPERM for an unsafe source outranks the domain's
// EACCES, the other way around from the EPERM that vfs_link() itself reports
// for a directory.
//
// A source is unsafe when the caller neither owns it nor may both read and
// write it, so the test hands it to another user and drops the capabilities
// that would exempt the caller.
TEST(LandlockV1Test, LinkOfUnsafeSourceReportsEpermNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_FOWNER)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_DAC_OVERRIDE)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_CHOWN)));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  // Mode 0644 owned by another user: readable but not writable by the caller.
  ASSERT_THAT(chmod(src_file.path().c_str(), 0644), SyscallSucceeds());
  constexpr uid_t kNobody = 65534;
  SKIP_IF(chown(src_file.path().c_str(), kNobody, kNobody) != 0);
  static std::string src;
  static std::string dst;
  src = src_file.path();
  dst = JoinPath(dir.path(), "hardlink");

  auto drop = [] {
    return SetCapability(CAP_FOWNER, false).ok() &&
           SetCapability(CAP_DAC_OVERRIDE, false).ok();
  };

  // The control establishes that the link really is refused as unsafe, so that
  // the EPERM below is not the protected_hardlinks check quietly not applying.
  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (!drop()) {
      _exit(kSetup);
    }
    _exit(ClassifyErrno(link(src.c_str(), dst.c_str())));
  }));
  SKIP_IF(!WIFEXITED(control) || WEXITSTATUS(control) != kErrPerm);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (!drop()) {
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

// Creates an empty regular file at path.
void CreateFile(const std::string& path) {
  int fd = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  ASSERT_THAT(fd, SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());
}

// A rule is attached to the file it was added for, the way Linux attaches it to
// a struct inode, rather than to the name the file had at the time. These tests
// reach a covered file by a name it did not have when the rule was added.

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

  // A file alongside the link, to show that the rule reaches the link because
  // it names the covered file and not because the directory is unrestricted.
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
  // The child renames this directory, so let the enclosing directory's
  // recursive cleanup dispose of it under whatever name it ends up with.
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

    // The rename stays within one directory, so ABI v1 permits it given the
    // rights above.
    if (rename(dir.c_str(), renamed.c_str()) != 0) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(JoinPath(renamed, "f")));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// A rule is keyed by the file, not by the name it was added under: deleting
// the covered file and creating a new one at the same path must not let the
// old rule grant access to the new file. Linux guarantees this by holding the
// inode the rule refers to; gVisor by retiring the deleted file's inode
// number so a later file cannot inherit it, even if the host hands the same
// host inode number out again.
TEST(LandlockV1Test, RuleDiesWithTheFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string target;
  target = file.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    // Only READ_FILE is handled, so the unlink and the re-creation below are
    // unrestricted; the rule is added on the file itself.
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

// The counterpart: the rule keeps following the file for as long as any hard
// link to it remains, so removing one of two names must not retire it.
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
    // The mount has to be in place before the domain is enforced, since a
    // domain forbids changing the mount tree at all.
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

// A directory moved out of the subtree its bind mount exposes is disconnected:
// the mount's root is no longer among its ancestors, so a walk from a file
// under it reaches the root of the filesystem without passing the mount root.
// The rights that reaching the file through that mount carries are still the
// ones the mount root has, so a rule on the mount root applies. Implementations
// without the fix stop at the filesystem root and deny.
//
// This is erratum 3, from Linux commit 49c9e09d9610 ("landlock: Fix handling of
// disconnected directories"), so which answer is right depends on what the
// implementation reports.
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

    // The only way to name the file once its directory has been moved out of
    // the mount is through a descriptor opened before the move.
    int dirfd = open(JoinPath(mount_point, "b").c_str(),
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    TEST_PCHECK(dirfd >= 0);
    TEST_PCHECK(rename(dir.c_str(), moved_dir.c_str()) == 0);

    // The rule names the root of the bind mount, which is no longer an ancestor
    // of the file in the filesystem, only in the mount.
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, mount_root,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(ClassifyFs(openat(dirfd, "f", O_RDONLY)));
  }));
  const int want = LandlockErratumFixed(3) ? kAllowed : kDenied;
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == want)
      << "exit status " << status;
}

// Landlock has no right that grants a change to the mount tree, so a thread
// with a domain cannot make one however permissive its policy. These hooks
// return EPERM rather than the EACCES the filesystem access hooks return.
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
    // The same mount succeeds before the domain is enforced, so the failure
    // below is Landlock's and not a missing capability.
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
    // pivot_root(2) requires the new root to be a mount point other than the
    // current root, so give it one of its own.
    TEST_PCHECK(mount("none", new_root.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(put_old.c_str(), 0755) == 0);

    ApplyFsPolicy(kFsAccessV1, new_root, kFsAccessV1);
    // A pivot_root(2) that Landlock let through would fail with EINVAL, not
    // EPERM, if this setup were wrong.
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

// The mount hooks run where Linux places them, which is after the syscall has
// copied in its arguments and resolved the paths it was given. A denial
// therefore never hides a malformed call: the errno the call would have failed
// with without a domain is still the one reported.

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

// umount(2) is the one mount hook Linux runs late: can_umount() rejects a path
// that names no mount of ours before do_umount() reaches
// security_sb_umount().
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

// Writing to a file that exists only in an overlay's lower layer copies it up,
// which makes the filesystem itself create and open the copy in the upper
// layer. Those internal operations run under the credentials the overlay
// captured when it was mounted, which carry no domain, so the policy is applied
// once to the write the caller asked for and not again to the layer files it
// happens to touch. A rule can only ever name what is reachable through the
// merged directory, so checking the layers would deny a write the policy
// plainly grants.
//
// Matches Linux, which reaches the domain through cred->security and so drops
// it in ovl_override_creds().
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
    // The layers need a filesystem of their own: overlayfs refuses an upper
    // layer that is itself on an overlay, which is what a container's temporary
    // directory usually is.
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(lower.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(upper.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(work.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(merged.c_str(), 0777) == 0);

    // The file exists only in the lower layer, so opening it for writing
    // through the merged directory is what forces the copy-up.
    int lower_fd = open(source.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    TEST_PCHECK(lower_fd >= 0);
    TEST_PCHECK(close(lower_fd) == 0);

    if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
      // No usable overlayfs here, so there is no copy-up to observe.
      _exit(kSetup);
    }

    ApplyFsPolicy(kFsAccessV1, merged, kFsAccessV1);
    _exit(ClassifyFs(open(target.c_str(), O_WRONLY)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// A rule names a file, and a copy-up does not make a new file: the file the
// rule was added on is the same file after the overlay moves it to the upper
// layer, so the rule still grants its rights. Linux gets this for free because
// the rule holds a reference to the overlayfs inode, which the copy-up does not
// replace.
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

    // The rule is added on the file itself, while it exists only in the lower
    // layer.
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  target,
                  LANDLOCK_ACCESS_FS_READ_FILE |
                      LANDLOCK_ACCESS_FS_WRITE_FILE);

    // Opening the file for writing copies it up, and closing the descriptor
    // lets the kernel forget everything it cached about the file. What it finds
    // when it looks the file up again lives in the upper layer only.
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

// The overlay checks the policy before copying the parent up, so that a denied
// removal leaves the layers untouched. It must still resolve the victim first:
// removing a name that does not exist is ENOENT whatever the policy says.
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

// A path names a different file at different moments. An operation resolves it
// once and acts on what that resolution found; the policy must be applied to
// that same file. Checking a separate resolution of the same path leaves a
// window in which the two disagree, and an operation can then land on a file
// the check never saw.
//
// These tests swap a symlink out from under a path while the operation runs.
// They assert only that nothing ever landed in the directory the policy does
// not cover, so a run that never wins the race still passes and they cannot
// flake; a run that does win fails only if the operation escaped.

constexpr int kRaceIterations = 300;

// Builds the layout the race tests share: covered/ and uncovered/ hold the
// files an operation might reach, and swap/link points at one of them.
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

// Repoints link at covered and uncovered in turn until stop is set. The rename
// is atomic, so a path through link always resolves to one of the two. Requires
// MAKE_SYM and REMOVE_FILE beneath the directory holding link.
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

// Removes the symlinks the swapping leaves behind. TempPath's recursive delete
// follows a symlink to a directory and then cannot remove what it found.
void RemoveSwapLinks(const std::string& link) {
  EXPECT_THAT(unlink(link.c_str()), SyscallSucceeds());
  unlink((link + ".tmp").c_str());
}

// Each iteration creates a name of its own, so no create ever finds the file
// already there and every one of them is a fresh attempt.
TEST(LandlockV1Test, CreateThroughSwappedSymlinkStaysUnderRule) {
  SKIP_IF(LandlockAbiVersion() < 1);
  // A cooperative save between two of the racing operations decides the race
  // for them, and one per syscall of the setup below costs minutes.
  const DisableSave ds;

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string covered, uncovered, swap_dir, link;
  ASSERT_NO_FATAL_FAILURE(
      MakeRaceDirs(base.path(), &covered, &uncovered, &swap_dir, &link));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kFsAccessV1);
    // Both directories grant the right to write the new file, so that the only
    // thing standing between a create and the uncovered directory is MAKE_REG.
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

    // Some creates have to have gone through, or the swapping left the link
    // pointing at the uncovered directory for the whole run and the test
    // proved nothing.
    _exit(created > 0 ? kAllowed : kSetup);
  }));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;

  // Checked here because reading the uncovered directory is not something the
  // policy allows the child to do.
  EXPECT_THAT(ASSERT_NO_ERRNO_AND_VALUE(ListDir(uncovered, /*skipdots=*/true)),
              ::testing::IsEmpty());
  RemoveSwapLinks(link);
}

// The same for the other direction: an unlink must not remove a file the policy
// does not cover, however the path it was given resolves.
TEST(LandlockV1Test, UnlinkThroughSwappedSymlinkStaysUnderRule) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const DisableSave ds;

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string covered, uncovered, swap_dir, link;
  ASSERT_NO_FATAL_FAILURE(
      MakeRaceDirs(base.path(), &covered, &uncovered, &swap_dir, &link));

  // The same names beneath both directories, so an unlink through the link has
  // something to remove whichever way it resolves.
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

  EXPECT_THAT(ASSERT_NO_ERRNO_AND_VALUE(ListDir(uncovered, /*skipdots=*/true)),
              ::testing::SizeIs(kRaceIterations));
  RemoveSwapLinks(link);
}

// Files that live on a sentry-internal mount are reachable through procfs but
// can never be named by a rule, because no path leads to the mount itself.
// Landlock allows them unconditionally rather than making them permanently
// inaccessible; see is_nouser_or_private() and the MNT_INTERNAL case of
// is_access_to_paths_allowed() in Linux.
//
// Each of these enforces a domain that handles read and write with no rules at
// all, so nothing on an ordinary filesystem would be openable.

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

// A socket has no path, but its procfs entry must still be openable for the
// same reason. Reopening it yields ENXIO on Linux rather than a Landlock
// denial, so the test only insists that it is not EACCES.
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

// A POSIX message queue lives on the mqueue filesystem, which is mounted
// internally for each IPC namespace but is a mountable filesystem all the same.
// mq_open(2) therefore goes through the same open hook as open(2), and a domain
// that handles the rights the open needs denies it unless a rule names the
// queue or the mqueue root, neither of which is reachable by a path here.
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

// The denial above comes from the rights the open requires, not from mqueue
// being off limits to sandboxed threads in general: a domain that handles no
// right an open needs leaves mq_open(2) alone.
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

// The walk that mq_open(2) performs reaches the root of the mqueue filesystem,
// so a rule added on a mount of it grants access to the queues beneath. This is
// the only way to name them: the mount that mq_open(2) itself uses is not in
// any path.
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

// Reconfiguring a superblock through a filesystem context descriptor changes
// the mount tree just as mount(2) with MS_REMOUNT does, so it is refused
// outright while a domain is active, whatever rights that domain handles.
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
    // fsmount(2) leaves the context ready to reconfigure the superblock it
    // created, which is the only way to reach FSCONFIG_CMD_RECONFIGURE
    // without fspick(2).
    int mount_fd = syscall(SYS_fsmount, fs_fd, 0, 0);
    if (mount_fd < 0) {
      _exit(kSetup);
    }

    // The domain handles a right that no reconfiguration could ever need, to
    // show that the denial does not depend on the rights it handles.
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));

    _exit(ClassifyMount(syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_RECONFIGURE,
                                nullptr, nullptr, 0)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}

// Landlock scopes ptrace: a thread confined by a domain may only trace a target
// confined by that same domain or a descendant of it. Otherwise a sandboxed
// thread could escape by driving a less restricted one.
//
// The domains below handle only LANDLOCK_ACCESS_FS_MAKE_DIR, which no operation
// in these tests performs. Any denial therefore comes from the ptrace scoping
// rule rather than from a filesystem access right.

// ForkTracee forks a process that optionally stacks a second Landlock layer on
// top of whatever it inherited, then blocks until *stop_fd is closed. It has
// returned only once the tracee is ready to be traced. Must be called from a
// forked test process: it exits the caller on failure.
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
    // Closing the write end reports readiness as EOF on the read end.
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

// TryAttach attaches to tracee, detaches again if that succeeded, then reaps it.
ChildResult TryAttach(pid_t tracee, int stop_fd) {
  int rc = ptrace(PTRACE_ATTACH, tracee, nullptr, nullptr);
  int err = errno;
  if (rc == 0) {
    // PTRACE_ATTACH stops the tracee; wait for the stop before detaching.
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
    // Fork the tracee first so that it never inherits the domain. It is a
    // child of the tracer, so YAMA's relational scope permits the attach and
    // only Landlock can deny it.
    int stop_fd;
    pid_t tracee = ForkTracee(/*extra_layer=*/false, &stop_fd);
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
    pid_t tracee = ForkTracee(/*extra_layer=*/false, &stop_fd);
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, PtraceAttachAllowedForMoreRestrictedTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    // The tracee stacks a further layer, making it a descendant domain.
    int stop_fd;
    pid_t tracee = ForkTracee(/*extra_layer=*/true, &stop_fd);
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// Reading another thread's memory through procfs is gated by the same check, so
// the scoping rule cannot be sidestepped by opening /proc/[pid]/mem directly.
TEST(LandlockV1Test, ProcMemOfUnsandboxedTargetIsInaccessible) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int stop_fd;
    pid_t tracee = ForkTracee(/*extra_layer=*/false, &stop_fd);
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

// PTRACE_TRACEME is checked with the same polarity: the prospective tracer is
// the parent, so a sandboxed parent may not be asked to trace an unsandboxed
// child.
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
      // Wait for the parent to enforce its domain before asking to be traced.
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

// The domain survives execve: the exec'd image is enforced, not just the
// process that called landlock_restrict_self(2). The policy lets the shell
// and its libraries be read and executed but grants WRITE_FILE nowhere, so
// the shell starts and its redirect fails.
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

  // Control: without a domain the shell and its redirect succeed, so the
  // failure below is the domain's doing.
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
  // The denied redirect must not have truncated or written the file.
  struct stat st;
  ASSERT_THAT(stat(enforced_target.c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_size, 0);
}

// The domain survives a change of identity: credentials are rebuilt by
// setuid(2), and the domain must come along, as it lives in Linux's cred
// blob.
TEST(LandlockV1Test, DomainSurvivesSetuid) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  // The file lives directly under /tmp: TEST_TMPDIR's ancestors may not be
  // searchable by the unprivileged uid, and the control below would skip the
  // test.
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn("/tmp"));
  static std::string target;
  target = file.path();
  constexpr uid_t kNobody = 65534;

  // Control: after setuid alone, ordinary permissions still let the file be
  // read, so the denial below can only be the domain's.
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

// landlock_restrict_self(2) restricts the calling thread only; a sibling
// thread of the same process stays unrestricted, as domains are per-thread.
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
    // The main thread never restricted itself.
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kSetup);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

// The other direction: a thread created after the restriction inherits it.
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

// A child that sandboxes itself does not restrict its parent; the inverse of
// RestrictionInheritedAcrossFork.
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

// Sibling domains — neither an ancestor of the other — cannot trace each
// other, whichever is "larger".
TEST(LandlockV1Test, PtraceAttachDeniedBetweenSiblingDomains) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    // The tracee forks first, so it does not inherit the tracer's layer, and
    // stacks a layer of its own: two domains, neither nested in the other.
    int stop_fd;
    pid_t tracee = ForkTracee(/*extra_layer=*/true, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    _exit(TryAttach(tracee, stop_fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

// PTRACE_TRACEME succeeds when the would-be tracer's domain is the child's
// own, inherited across the fork.
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

// process_vm_readv(2) is gated by the same ptrace access check, so the
// scoping cannot be sidestepped by reading memory directly.
TEST(LandlockV1Test, ProcessVmReadvDeniedForUnsandboxedTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  static char remote_buf[8] = "watched";
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int stop_fd;
    pid_t tracee = ForkTracee(/*extra_layer=*/false, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));

    char local_buf[sizeof(remote_buf)] = {};
    struct iovec local = {local_buf, sizeof(local_buf)};
    // The tracee is a fork of this process, so remote_buf has the same
    // address there.
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
