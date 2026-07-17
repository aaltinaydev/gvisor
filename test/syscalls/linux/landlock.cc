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

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <functional>
#include <string>
#include <atomic>
#include <thread>

#include "absl/synchronization/mutex.h"
#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

// Define syscall numbers if not present
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

// Landlock flags
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#ifndef LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF
#define LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF (1U << 0)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
#define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON (1U << 1)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF
#define LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF (1U << 2)
#endif

// Rule types
#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif

// Access rights (v1)
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)

// Access rights (v2)
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#define LANDLOCK_ACCESS_FS_ALL_V1                                         \
	(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |     \
	 LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |     \
	 LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	 LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |     \
	 LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |     \
	 LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |   \
	 LANDLOCK_ACCESS_FS_MAKE_SYM)

// Structs
struct landlock_ruleset_attr {
	uint64_t handled_access_fs;
	uint64_t handled_access_net;
	uint64_t scoped;
};

struct landlock_path_beneath_attr {
	uint64_t allowed_access;
	int32_t parent_fd;
} __attribute__((packed));

namespace gvisor
{
namespace testing
{
namespace
{

class LandlockTest : public ::testing::Test {
    protected:
	void SetUp() override
	{
		// Check if Landlock is supported by the kernel
		int version = syscall(__NR_landlock_create_ruleset, NULL, 0,
				      LANDLOCK_CREATE_RULESET_VERSION);
		if (version < 0) {
			if (errno == ENOSYS || errno == EOPNOTSUPP ||
			    errno == EPERM || errno == EACCES) {
				GTEST_SKIP()
					<< "Landlock not supported by kernel or blocked by security policy: "
					<< strerror(errno);
				return;
			}
			FAIL() << "Failed to check Landlock version: "
			       << strerror(errno);
		}
	}

	void RunInFork(std::function<void()> const &f)
	{
		pid_t pid = fork();
		ASSERT_GE(pid, 0);
		if (pid == 0) {
			f();
			if (::testing::Test::HasFailure()) {
				_exit(1);
			}
			_exit(0);
		}
		int status;
		ASSERT_THAT(waitpid(pid, &status, 0), SyscallSucceeds());
		ASSERT_TRUE(WIFEXITED(status));
		EXPECT_EQ(WEXITSTATUS(status), 0);
	}
};

TEST_F(LandlockTest, VersionCheck)
{
	int version = syscall(__NR_landlock_create_ruleset, NULL, 0,
			      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);
}

TEST_F(LandlockTest, CreateRulesetInvalidFlags)
{
	struct landlock_ruleset_attr attr = { 0 };
	EXPECT_THAT(syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr),
			    1 << 30),
		    SyscallFailsWithErrno(EINVAL));
}

TEST_F(LandlockTest, CreateRulesetInvalidSize)
{
	struct landlock_ruleset_attr attr = { 0 };
	EXPECT_THAT(syscall(__NR_landlock_create_ruleset, &attr, 7, 0),
		    SyscallFailsWithErrno(EINVAL));
}

TEST_F(LandlockTest, CreateRulesetBadPointer)
{
	EXPECT_THAT(syscall(__NR_landlock_create_ruleset, nullptr, 8, 0),
		    SyscallFailsWithErrno(EFAULT));
	EXPECT_THAT(syscall(__NR_landlock_create_ruleset, (void *)-1, 8, 0),
		    SyscallFailsWithErrno(EFAULT));
}

TEST_F(LandlockTest, CreateRulesetEmptyAccess)
{
	struct landlock_ruleset_attr attr = { .handled_access_fs = 0 };
	EXPECT_THAT(syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr),
			    0),
		    SyscallFailsWithErrno(ENOMSG));
}

TEST_F(LandlockTest, AddRuleInvalidFlags)
{
	struct landlock_ruleset_attr attr = { LANDLOCK_ACCESS_FS_READ_FILE };
	int ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_GE(ruleset_fd, 0);
	auto cleanup_fd = FileDescriptor(ruleset_fd);

	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = AT_FDCWD,
	};

	EXPECT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
			    LANDLOCK_RULE_PATH_BENEATH, &path_attr, 1),
		    SyscallFailsWithErrno(EINVAL));
}

TEST_F(LandlockTest, AddRuleInvalidRulesetFd)
{
	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = AT_FDCWD,
	};
	EXPECT_THAT(syscall(__NR_landlock_add_rule, -1,
			    LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
		    SyscallFailsWithErrno(EBADF));

	int null_fd = open("/dev/null", O_RDONLY);
	ASSERT_GE(null_fd, 0);
	auto cleanup_null = FileDescriptor(null_fd);
	EXPECT_THAT(syscall(__NR_landlock_add_rule, null_fd,
			    LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
		    SyscallFailsWithErrno(EBADFD));
}

TEST_F(LandlockTest, AddRuleInvalidRuleType)
{
	struct landlock_ruleset_attr attr = { LANDLOCK_ACCESS_FS_READ_FILE };
	int ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_GE(ruleset_fd, 0);
	auto cleanup_fd = FileDescriptor(ruleset_fd);

	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = AT_FDCWD,
	};
	EXPECT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd, 0, &path_attr,
			    0),
		    SyscallFailsWithErrno(EINVAL));
}

TEST_F(LandlockTest, AddRuleInvalidAccess)
{
	struct landlock_ruleset_attr attr = { LANDLOCK_ACCESS_FS_READ_FILE };
	int ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_GE(ruleset_fd, 0);
	auto cleanup_fd = FileDescriptor(ruleset_fd);

	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE,
		.parent_fd = AT_FDCWD,
	};
	EXPECT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
			    LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
		    SyscallFailsWithErrno(EINVAL));
}

TEST_F(LandlockTest, AddRuleEmptyAccess)
{
	struct landlock_ruleset_attr attr = { LANDLOCK_ACCESS_FS_READ_FILE };
	int ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_GE(ruleset_fd, 0);
	auto cleanup_fd = FileDescriptor(ruleset_fd);

	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = 0,
		.parent_fd = AT_FDCWD,
	};
	EXPECT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
			    LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
		    SyscallFailsWithErrno(ENOMSG));
}

TEST_F(LandlockTest, AddRuleInvalidParentFd)
{
	struct landlock_ruleset_attr attr = { LANDLOCK_ACCESS_FS_READ_FILE };
	int ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_GE(ruleset_fd, 0);
	auto cleanup_fd = FileDescriptor(ruleset_fd);

	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = -1,
	};
	EXPECT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
			    LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
		    SyscallFailsWithErrno(EBADF));

	struct landlock_path_beneath_attr path_attr2 = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = ruleset_fd,
	};
	EXPECT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
			    LANDLOCK_RULE_PATH_BENEATH, &path_attr2, 0),
		    SyscallFailsWithErrno(EBADFD));
}

TEST_F(LandlockTest, AddRuleInternalMounts)
{
	struct landlock_ruleset_attr attr = { LANDLOCK_ACCESS_FS_READ_FILE };
	int ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_GE(ruleset_fd, 0);
	auto cleanup_fd = FileDescriptor(ruleset_fd);

	// Test with pipe
	int pipe_fds[2];
	ASSERT_THAT(pipe(pipe_fds), SyscallSucceeds());
	auto cleanup_pipe0 = FileDescriptor(pipe_fds[0]);
	auto cleanup_pipe1 = FileDescriptor(pipe_fds[1]);

	struct landlock_path_beneath_attr pipe_path_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = pipe_fds[0],
	};
	EXPECT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
			    LANDLOCK_RULE_PATH_BENEATH, &pipe_path_attr, 0),
		    SyscallFailsWithErrno(EBADFD));

	// Test with socket
	int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_GE(sock_fd, 0);
	auto cleanup_sock = FileDescriptor(sock_fd);

	struct landlock_path_beneath_attr sock_path_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = sock_fd,
	};
	EXPECT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
			    LANDLOCK_RULE_PATH_BENEATH, &sock_path_attr, 0),
		    SyscallFailsWithErrno(EBADFD));
}

TEST_F(LandlockTest, AddRuleReadOnlyRulesetFd)
{
	struct landlock_ruleset_attr attr = { LANDLOCK_ACCESS_FS_READ_FILE };
	int ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_GE(ruleset_fd, 0);
	auto cleanup_fd = FileDescriptor(ruleset_fd);

	std::string proc_path = "/proc/self/fd/" + std::to_string(ruleset_fd);
	int ro_ruleset_fd = open(proc_path.c_str(), O_RDONLY);
	if (ro_ruleset_fd < 0 &&
	    (errno == ENODEV || errno == ENXIO || errno == EACCES ||
	     errno == EPERM || errno == ENOENT || errno == EINVAL ||
	     errno == EOPNOTSUPP)) {
		GTEST_SKIP()
			<< "Reopening anon_inodes via /proc/self/fd is not supported: "
			<< strerror(errno);
		return;
	}
	ASSERT_GE(ro_ruleset_fd, 0) << "Failed to reopen ruleset FD read-only";
	auto cleanup_ro_fd = FileDescriptor(ro_ruleset_fd);

	int dir_fd = open(".", O_PATH | O_DIRECTORY);
	ASSERT_GE(dir_fd, 0);
	auto cleanup_dir = FileDescriptor(dir_fd);

	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
		.parent_fd = dir_fd,
	};
	EXPECT_THAT(syscall(__NR_landlock_add_rule, ro_ruleset_fd,
			    LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
		    SyscallFailsWithErrno(EPERM));
}

TEST_F(LandlockTest, RestrictSelfInvalidFlags)
{
	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			LANDLOCK_ACCESS_FS_READ_FILE
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_fd = FileDescriptor(ruleset_fd);

		EXPECT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd,
				    1U << 3),
			    SyscallFailsWithErrno(EINVAL));
	});
}

TEST_F(LandlockTest, RestrictSelfValidFlags)
{
	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			LANDLOCK_ACCESS_FS_READ_FILE
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_fd = FileDescriptor(ruleset_fd);

		EXPECT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd,
				    LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF),
			    SyscallSucceeds());
	});

	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			LANDLOCK_ACCESS_FS_READ_FILE
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_fd = FileDescriptor(ruleset_fd);

		EXPECT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd,
				    LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON),
			    SyscallSucceeds());
	});

	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			LANDLOCK_ACCESS_FS_READ_FILE
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_fd = FileDescriptor(ruleset_fd);

		EXPECT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd,
				    LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF),
			    SyscallSucceeds());
	});

	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			LANDLOCK_ACCESS_FS_READ_FILE
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_fd = FileDescriptor(ruleset_fd);

		uint32_t flags = LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF |
				 LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON |
				 LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF;
		EXPECT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd,
				    flags),
			    SyscallSucceeds());
	});
}

TEST_F(LandlockTest, RestrictSelfInvalidRulesetFd)
{
	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		EXPECT_THAT(syscall(__NR_landlock_restrict_self, -1, 0),
			    SyscallFailsWithErrno(EBADF));

		int null_fd = open("/dev/null", O_RDONLY);
		ASSERT_GE(null_fd, 0);
		auto cleanup_null = FileDescriptor(null_fd);
		EXPECT_THAT(syscall(__NR_landlock_restrict_self, null_fd, 0),
			    SyscallFailsWithErrno(EBADFD));
	});
}

TEST_F(LandlockTest, RestrictSelfWriteOnlyRulesetFd)
{
	struct landlock_ruleset_attr attr = { LANDLOCK_ACCESS_FS_READ_FILE };
	int ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_GE(ruleset_fd, 0);
	auto cleanup_fd = FileDescriptor(ruleset_fd);

	std::string proc_path = "/proc/self/fd/" + std::to_string(ruleset_fd);
	int wo_ruleset_fd = open(proc_path.c_str(), O_WRONLY);
	if (wo_ruleset_fd < 0 &&
	    (errno == ENODEV || errno == ENXIO || errno == EACCES ||
	     errno == EPERM || errno == ENOENT || errno == EINVAL ||
	     errno == EOPNOTSUPP)) {
		GTEST_SKIP()
			<< "Reopening anon_inodes via /proc/self/fd is not supported: "
			<< strerror(errno);
		return;
	}
	ASSERT_GE(wo_ruleset_fd, 0) << "Failed to reopen ruleset FD write-only";
	auto cleanup_wo_fd = FileDescriptor(wo_ruleset_fd);

	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		EXPECT_THAT(syscall(__NR_landlock_restrict_self, wo_ruleset_fd,
				    0),
			    SyscallFailsWithErrno(EPERM));
	});
}

TEST_F(LandlockTest, RestrictSelfRequiresNoNewPrivsOrSysAdmin)
{
	struct landlock_ruleset_attr attr = { LANDLOCK_ACCESS_FS_READ_FILE };
	int ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_GE(ruleset_fd, 0);
	auto cleanup_fd = FileDescriptor(ruleset_fd);

	RunInFork([&]() {
		ASSERT_NO_ERRNO(SetCapability(CAP_SYS_ADMIN, false));

		// If no_new_privs is already set (e.g. by the test runner), we cannot
		// verify that restrict_self fails without it.
		int no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
		ASSERT_GE(no_new_privs, 0);
		if (!no_new_privs) {
			EXPECT_THAT(syscall(__NR_landlock_restrict_self,
					    ruleset_fd, 0),
				    SyscallFailsWithErrno(EPERM));
		}

		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		EXPECT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd, 0),
			    SyscallSucceeds());
	});
}

TEST_F(LandlockTest, BasicPathRestrictions)
{
	std::string tmp_dir = NewTempAbsPath();
	ASSERT_THAT(mkdir(tmp_dir.c_str(), 0777), SyscallSucceeds());

	std::string dir_allowed = JoinPath(tmp_dir, "allowed");
	std::string dir_denied = JoinPath(tmp_dir, "denied");
	ASSERT_THAT(mkdir(dir_allowed.c_str(), 0777), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir_denied.c_str(), 0777), SyscallSucceeds());

	std::string file_allowed = JoinPath(dir_allowed, "file");
	std::string file_denied = JoinPath(dir_denied, "file");

	int fd;
	ASSERT_THAT(fd = open(file_allowed.c_str(), O_RDWR | O_CREAT, 0666),
		    SyscallSucceeds());
	close(fd);
	ASSERT_THAT(fd = open(file_denied.c_str(), O_RDWR | O_CREAT, 0666),
		    SyscallSucceeds());
	close(fd);

	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
					     LANDLOCK_ACCESS_FS_WRITE_FILE,
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_ruleset = FileDescriptor(ruleset_fd);

		int allowed_dfd =
			open(dir_allowed.c_str(), O_PATH | O_DIRECTORY);
		ASSERT_GE(allowed_dfd, 0);
		auto cleanup_allowed = FileDescriptor(allowed_dfd);

		struct landlock_path_beneath_attr path_attr = {
			.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
			.parent_fd = allowed_dfd,
		};
		ASSERT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
				    LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
			    SyscallSucceeds());

		ASSERT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd, 0),
			    SyscallSucceeds());

		int rfd = open(file_allowed.c_str(), O_RDONLY);
		EXPECT_GE(rfd, 0);
		if (rfd >= 0)
			close(rfd);

		EXPECT_THAT(open(file_allowed.c_str(), O_WRONLY),
			    SyscallFailsWithErrno(EACCES));

		EXPECT_THAT(open(file_denied.c_str(), O_RDONLY),
			    SyscallFailsWithErrno(EACCES));

		EXPECT_THAT(open(file_denied.c_str(), O_WRONLY),
			    SyscallFailsWithErrno(EACCES));
	});

	unlink(file_allowed.c_str());
	unlink(file_denied.c_str());
	rmdir(dir_allowed.c_str());
	rmdir(dir_denied.c_str());
	rmdir(tmp_dir.c_str());
}

TEST_F(LandlockTest, DirectoryOperations)
{
	std::string tmp_dir = NewTempAbsPath();
	ASSERT_THAT(mkdir(tmp_dir.c_str(), 0777), SyscallSucceeds());

	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_MAKE_DIR |
					     LANDLOCK_ACCESS_FS_REMOVE_DIR,
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_ruleset = FileDescriptor(ruleset_fd);

		ASSERT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd, 0),
			    SyscallSucceeds());

		std::string new_dir = JoinPath(tmp_dir, "new_dir");
		EXPECT_THAT(mkdir(new_dir.c_str(), 0777),
			    SyscallFailsWithErrno(EACCES));
	});

	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_MAKE_DIR |
					     LANDLOCK_ACCESS_FS_REMOVE_DIR,
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_ruleset = FileDescriptor(ruleset_fd);

		int tmp_dfd = open(tmp_dir.c_str(), O_PATH | O_DIRECTORY);
		ASSERT_GE(tmp_dfd, 0);
		auto cleanup_tmp = FileDescriptor(tmp_dfd);

		struct landlock_path_beneath_attr path_attr = {
			.allowed_access = LANDLOCK_ACCESS_FS_MAKE_DIR |
					  LANDLOCK_ACCESS_FS_REMOVE_DIR,
			.parent_fd = tmp_dfd,
		};
		ASSERT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
				    LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
			    SyscallSucceeds());

		ASSERT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd, 0),
			    SyscallSucceeds());

		std::string new_dir = JoinPath(tmp_dir, "new_dir");
		EXPECT_THAT(mkdir(new_dir.c_str(), 0777), SyscallSucceeds());
		EXPECT_THAT(rmdir(new_dir.c_str()), SyscallSucceeds());
	});

	rmdir(tmp_dir.c_str());
}

TEST_F(LandlockTest, RuleInheritance)
{
	std::string tmp_dir = NewTempAbsPath();
	ASSERT_THAT(mkdir(tmp_dir.c_str(), 0777), SyscallSucceeds());

	std::string parent = JoinPath(tmp_dir, "parent");
	std::string child = JoinPath(parent, "child");
	std::string grandchild = JoinPath(child, "grandchild");
	ASSERT_THAT(mkdir(parent.c_str(), 0777), SyscallSucceeds());
	ASSERT_THAT(mkdir(child.c_str(), 0777), SyscallSucceeds());
	ASSERT_THAT(mkdir(grandchild.c_str(), 0777), SyscallSucceeds());

	std::string file = JoinPath(grandchild, "file");
	int fd;
	ASSERT_THAT(fd = open(file.c_str(), O_RDWR | O_CREAT, 0666),
		    SyscallSucceeds());
	close(fd);

	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_ruleset = FileDescriptor(ruleset_fd);

		int parent_dfd = open(parent.c_str(), O_PATH | O_DIRECTORY);
		ASSERT_GE(parent_dfd, 0);
		auto cleanup_parent = FileDescriptor(parent_dfd);

		struct landlock_path_beneath_attr path_attr = {
			.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
			.parent_fd = parent_dfd,
		};
		ASSERT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
				    LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0),
			    SyscallSucceeds());

		ASSERT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd, 0),
			    SyscallSucceeds());

		int rfd = open(file.c_str(), O_RDONLY);
		EXPECT_GE(rfd, 0);
		if (rfd >= 0)
			close(rfd);
	});

	unlink(file.c_str());
	rmdir(grandchild.c_str());
	rmdir(child.c_str());
	rmdir(parent.c_str());
	rmdir(tmp_dir.c_str());
}

TEST_F(LandlockTest, StackingRulesetsLimit)
{
	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		bool hit_limit = false;
		for (int i = 0; i < 17; ++i) {
			struct landlock_ruleset_attr attr = {
				.handled_access_fs =
					LANDLOCK_ACCESS_FS_READ_FILE,
			};
			int ruleset_fd = syscall(__NR_landlock_create_ruleset,
						 &attr, sizeof(attr), 0);
			ASSERT_GE(ruleset_fd, 0)
				<< "Failed to create ruleset at layer " << i;
			auto cleanup_ruleset = FileDescriptor(ruleset_fd);

			long res = syscall(__NR_landlock_restrict_self,
					   ruleset_fd, 0);
			if (res < 0) {
				ASSERT_EQ(errno, E2BIG)
					<< "Failed with unexpected errno at layer "
					<< i << ": " << strerror(errno);
				hit_limit = true;
				break;
			}
		}
		EXPECT_TRUE(hit_limit)
			<< "Did not hit the 16-layer stacking limit";
	});
}

TEST_F(LandlockTest, CrossDirectoryRenameLinkDenied)
{
	std::string tmp_dir = NewTempAbsPath();
	ASSERT_THAT(mkdir(tmp_dir.c_str(), 0777), SyscallSucceeds());

	std::string dir1 = JoinPath(tmp_dir, "dir1");
	std::string dir2 = JoinPath(tmp_dir, "dir2");
	ASSERT_THAT(mkdir(dir1.c_str(), 0777), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir2.c_str(), 0777), SyscallSucceeds());

	std::string file1 = JoinPath(dir1, "file1");
	int fd;
	ASSERT_THAT(fd = open(file1.c_str(), O_RDWR | O_CREAT, 0666),
		    SyscallSucceeds());
	close(fd);

	RunInFork([&]() {
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		uint64_t handled_access = LANDLOCK_ACCESS_FS_WRITE_FILE |
					  LANDLOCK_ACCESS_FS_REMOVE_FILE |
					  LANDLOCK_ACCESS_FS_MAKE_REG;
		uint64_t allowed_access = handled_access;

		int version = syscall(__NR_landlock_create_ruleset, NULL, 0,
				      LANDLOCK_CREATE_RULESET_VERSION);
		if (version >= 2) {
			handled_access |= LANDLOCK_ACCESS_FS_REFER;
		}

		struct landlock_ruleset_attr attr = {
			.handled_access_fs = handled_access,
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_ruleset = FileDescriptor(ruleset_fd);

		int dir1_fd = open(dir1.c_str(), O_PATH | O_DIRECTORY);
		ASSERT_GE(dir1_fd, 0);
		auto cleanup_dir1 = FileDescriptor(dir1_fd);

		int dir2_fd = open(dir2.c_str(), O_PATH | O_DIRECTORY);
		ASSERT_GE(dir2_fd, 0);
		auto cleanup_dir2 = FileDescriptor(dir2_fd);

		struct landlock_path_beneath_attr path_attr1 = {
			.allowed_access = allowed_access,
			.parent_fd = dir1_fd,
		};
		ASSERT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
				    LANDLOCK_RULE_PATH_BENEATH, &path_attr1, 0),
			    SyscallSucceeds());

		struct landlock_path_beneath_attr path_attr2 = {
			.allowed_access = allowed_access,
			.parent_fd = dir2_fd,
		};
		ASSERT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd,
				    LANDLOCK_RULE_PATH_BENEATH, &path_attr2, 0),
			    SyscallSucceeds());

		ASSERT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd, 0),
			    SyscallSucceeds());

		std::string file1_renamed = JoinPath(dir1, "file1_renamed");
		EXPECT_THAT(rename(file1.c_str(), file1_renamed.c_str()),
			    SyscallSucceeds());
		EXPECT_THAT(rename(file1_renamed.c_str(), file1.c_str()),
			    SyscallSucceeds());

		std::string file1_link = JoinPath(dir1, "file1_link");
		EXPECT_THAT(link(file1.c_str(), file1_link.c_str()),
			    SyscallSucceeds());
		EXPECT_THAT(unlink(file1_link.c_str()), SyscallSucceeds());

		std::string file2 = JoinPath(dir2, "file2");
		EXPECT_THAT(
			rename(file1.c_str(), file2.c_str()),
			SyscallFailsWithErrno(::testing::AnyOf(EXDEV, EACCES)));

		EXPECT_THAT(
			link(file1.c_str(), file2.c_str()),
			SyscallFailsWithErrno(::testing::AnyOf(EXDEV, EACCES)));
	});

	unlink(file1.c_str());
	rmdir(dir1.c_str());
	rmdir(dir2.c_str());
	rmdir(tmp_dir.c_str());
}

TEST_F(LandlockTest, NoRestrictionByDefault)
{
	std::string tmp_dir = NewTempAbsPath();
	ASSERT_THAT(mkdir(tmp_dir.c_str(), 0777), SyscallSucceeds());
	std::string file = JoinPath(tmp_dir, "file");

	struct landlock_ruleset_attr attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_GE(ruleset_fd, 0);
	auto cleanup_ruleset = FileDescriptor(ruleset_fd);

	int fd = open(file.c_str(), O_RDWR | O_CREAT, 0666);
	EXPECT_GE(fd, 0);
	if (fd >= 0) {
		EXPECT_THAT(write(fd, "test", 4), SyscallSucceedsWithValue(4));
		close(fd);
	}

	int rfd = open(file.c_str(), O_RDONLY);
	EXPECT_GE(rfd, 0);
	if (rfd >= 0)
		close(rfd);

	unlink(file.c_str());
	rmdir(tmp_dir.c_str());
}

TEST_F(LandlockTest, RestrictSelfDoesNotAffectOtherState)
{
	RunInFork([&]() {
		uid_t uid = getuid();
		gid_t gid = getgid();

		int null_fd = open("/dev/null", O_RDONLY);
		ASSERT_GE(null_fd, 0);
		auto cleanup_null = FileDescriptor(null_fd);

		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_ruleset = FileDescriptor(ruleset_fd);

		ASSERT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd, 0),
			    SyscallSucceeds());

		EXPECT_EQ(getuid(), uid);
		EXPECT_EQ(getgid(), gid);

		char buf[10];
		EXPECT_THAT(read(null_fd, buf, sizeof(buf)),
			    SyscallSucceedsWithValue(0));
	});
}

TEST_F(LandlockTest, RulesetMergeDentryRefcount)
{
	std::string tmp_dir = NewTempAbsPath();
	ASSERT_THAT(mkdir(tmp_dir.c_str(), 0777), SyscallSucceeds());
	std::string dir1 = JoinPath(tmp_dir, "dir1");
	std::string dir2 = JoinPath(tmp_dir, "dir2");
	ASSERT_THAT(mkdir(dir1.c_str(), 0777), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir2.c_str(), 0777), SyscallSucceeds());

	{
		int dir1_fd = open(dir1.c_str(), O_PATH | O_DIRECTORY);
		ASSERT_GE(dir1_fd, 0);
		auto cleanup_dir1 = FileDescriptor(dir1_fd);

		int dir2_fd = open(dir2.c_str(), O_PATH | O_DIRECTORY);
		ASSERT_GE(dir2_fd, 0);
		auto cleanup_dir2 = FileDescriptor(dir2_fd);

		RunInFork([&]() {
			ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
				    SyscallSucceeds());

			// Create R1
			struct landlock_ruleset_attr attr1 = {
				.handled_access_fs =
					LANDLOCK_ACCESS_FS_READ_FILE,
			};
			int ruleset_fd1 = syscall(__NR_landlock_create_ruleset,
						  &attr1, sizeof(attr1), 0);
			ASSERT_GE(ruleset_fd1, 0);
			auto cleanup_r1 = FileDescriptor(ruleset_fd1);

			struct landlock_path_beneath_attr path_attr1 = {
				.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
				.parent_fd = dir1_fd,
			};
			ASSERT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd1,
					    LANDLOCK_RULE_PATH_BENEATH,
					    &path_attr1, 0),
				    SyscallSucceeds());

			// Create R2
			struct landlock_ruleset_attr attr2 = {
				.handled_access_fs =
					LANDLOCK_ACCESS_FS_WRITE_FILE,
			};
			int ruleset_fd2 = syscall(__NR_landlock_create_ruleset,
						  &attr2, sizeof(attr2), 0);
			ASSERT_GE(ruleset_fd2, 0);
			auto cleanup_r2 = FileDescriptor(ruleset_fd2);

			struct landlock_path_beneath_attr path_attr2 = {
				.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE,
				.parent_fd = dir2_fd,
			};
			ASSERT_THAT(syscall(__NR_landlock_add_rule, ruleset_fd2,
					    LANDLOCK_RULE_PATH_BENEATH,
					    &path_attr2, 0),
				    SyscallSucceeds());

			// Restrict self with R1
			ASSERT_THAT(syscall(__NR_landlock_restrict_self,
					    ruleset_fd1, 0),
				    SyscallSucceeds());

			// Restrict self with R2 (merges with R1)
			ASSERT_THAT(syscall(__NR_landlock_restrict_self,
					    ruleset_fd2, 0),
				    SyscallSucceeds());
		});
	}

	rmdir(dir1.c_str());
	rmdir(dir2.c_str());
	rmdir(tmp_dir.c_str());
}

TEST_F(LandlockTest, MultiThreadedInheritance)
{
	std::string tmp_dir = NewTempAbsPath();
	ASSERT_THAT(mkdir(tmp_dir.c_str(), 0777), SyscallSucceeds());
	std::string file = JoinPath(tmp_dir, "file");
	int fd;
	ASSERT_THAT(fd = open(file.c_str(), O_RDWR | O_CREAT, 0666),
		    SyscallSucceeds());
	close(fd);

	RunInFork([&]() {
		absl::Mutex mu;
		bool thread_before_ready = false;
		bool thread_before_should_read = false;
		bool thread_before_done = false;
		bool thread_before_success = false;

		// 1. Spawn a thread BEFORE restricting the main thread.
		std::thread t_before([&]() {
			{
				absl::MutexLock l(&mu);
				thread_before_ready = true;
			}
			{
				absl::MutexLock l(&mu);
				mu.Await(absl::Condition(
					&thread_before_should_read));
			}
			// Attempt to read the file.
			int rfd = open(file.c_str(), O_RDONLY);
			{
				absl::MutexLock l(&mu);
				if (rfd >= 0) {
					thread_before_success = true;
					close(rfd);
				} else {
					thread_before_success = false;
				}
				thread_before_done = true;
			}
		});

		// Wait until the thread is ready.
		{
			absl::MutexLock l(&mu);
			mu.Await(absl::Condition(&thread_before_ready));
		}

		// 2. Restrict the main thread.
		ASSERT_THAT(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
			    SyscallSucceeds());

		struct landlock_ruleset_attr attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		auto cleanup_ruleset = FileDescriptor(ruleset_fd);

		ASSERT_THAT(syscall(__NR_landlock_restrict_self, ruleset_fd, 0),
			    SyscallSucceeds());

		// 3. Verify main thread (restricted) CANNOT read.
		EXPECT_THAT(open(file.c_str(), O_RDONLY),
			    SyscallFailsWithErrno(EACCES));

		// 4. Signal t_before to read. It should succeed.
		{
			absl::MutexLock l(&mu);
			thread_before_should_read = true;
		}
		{
			absl::MutexLock l(&mu);
			mu.Await(absl::Condition(&thread_before_done));
		}
		EXPECT_TRUE(thread_before_success);
		t_before.join();

		// 5. Spawn a thread AFTER restricting the main thread.
		bool thread_after_done = false;
		bool thread_after_failed_with_eacces = false;

		std::thread t_after([&]() {
			int rfd = open(file.c_str(), O_RDONLY);
			{
				absl::MutexLock l(&mu);
				if (rfd < 0 && errno == EACCES) {
					thread_after_failed_with_eacces = true;
				} else if (rfd >= 0) {
					close(rfd);
				}
				thread_after_done = true;
			}
		});

		{
			absl::MutexLock l(&mu);
			mu.Await(absl::Condition(&thread_after_done));
		}
		EXPECT_TRUE(thread_after_failed_with_eacces);
		t_after.join();
	});

	unlink(file.c_str());
	rmdir(tmp_dir.c_str());
}

TEST_F(LandlockTest, SiblingProcessIsolation)
{
	std::string tmp_dir = NewTempAbsPath();
	ASSERT_THAT(mkdir(tmp_dir.c_str(), 0777), SyscallSucceeds());
	std::string file = JoinPath(tmp_dir, "file");
	int fd;
	ASSERT_THAT(fd = open(file.c_str(), O_RDWR | O_CREAT, 0666),
		    SyscallSucceeds());
	close(fd);

	int pipe_parent_to_child1[2];
	int pipe_child1_to_parent[2];
	int pipe_parent_to_child2[2];

	ASSERT_THAT(pipe(pipe_parent_to_child1), SyscallSucceeds());
	ASSERT_THAT(pipe(pipe_child1_to_parent), SyscallSucceeds());
	ASSERT_THAT(pipe(pipe_parent_to_child2), SyscallSucceeds());

	auto cleanup_p1 = FileDescriptor(pipe_parent_to_child1[0]);
	auto cleanup_p2 = FileDescriptor(pipe_parent_to_child1[1]);
	auto cleanup_p3 = FileDescriptor(pipe_child1_to_parent[0]);
	auto cleanup_p4 = FileDescriptor(pipe_child1_to_parent[1]);
	auto cleanup_p5 = FileDescriptor(pipe_parent_to_child2[0]);
	auto cleanup_p6 = FileDescriptor(pipe_parent_to_child2[1]);

	pid_t pid1 = fork();
	ASSERT_GE(pid1, 0);
	if (pid1 == 0) {
		// Child 1
		close(pipe_parent_to_child1[1]);
		close(pipe_child1_to_parent[0]);
		close(pipe_parent_to_child2[0]);
		close(pipe_parent_to_child2[1]);

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			_exit(1);
		}

		struct landlock_ruleset_attr attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		if (ruleset_fd < 0) {
			_exit(2);
		}

		if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) < 0) {
			_exit(3);
		}

		if (open(file.c_str(), O_RDONLY) >= 0 || errno != EACCES) {
			_exit(4);
		}

		char c = 'a';
		if (write(pipe_child1_to_parent[1], &c, 1) != 1) {
			_exit(5);
		}

		if (read(pipe_parent_to_child1[0], &c, 1) != 1) {
			_exit(6);
		}

		_exit(0);
	}

	// Parent
	cleanup_p1.reset();
	cleanup_p4.reset();
	cleanup_p6.reset();

	char c;
	ASSERT_EQ(read(pipe_child1_to_parent[0], &c, 1), 1);

	pid_t pid2 = fork();
	ASSERT_GE(pid2, 0);
	if (pid2 == 0) {
		// Child 2
		close(pipe_parent_to_child1[0]);
		close(pipe_parent_to_child1[1]);
		close(pipe_child1_to_parent[0]);
		close(pipe_parent_to_child2[0]);

		int rfd = open(file.c_str(), O_RDONLY);
		if (rfd < 0) {
			_exit(1);
		}
		close(rfd);
		_exit(0);
	}

	// Parent again
	cleanup_p5.reset();

	c = 'b';
	ASSERT_EQ(write(pipe_parent_to_child1[1], &c, 1), 1);

	int status1, status2;
	ASSERT_THAT(waitpid(pid1, &status1, 0), SyscallSucceeds());
	ASSERT_THAT(waitpid(pid2, &status2, 0), SyscallSucceeds());

	EXPECT_TRUE(WIFEXITED(status1));
	EXPECT_EQ(WEXITSTATUS(status1), 0) << "Child 1 failed";

	EXPECT_TRUE(WIFEXITED(status2));
	EXPECT_EQ(WEXITSTATUS(status2), 0) << "Child 2 failed";

	unlink(file.c_str());
	rmdir(tmp_dir.c_str());
}

TEST_F(LandlockTest, CreateRulesetSizeTooBig)
{
	struct landlock_ruleset_attr attr = {};
	EXPECT_THAT(syscall(__NR_landlock_create_ruleset, &attr,
			    getpagesize() + 1, 0),
		    SyscallFailsWithErrno(E2BIG));
}

TEST_F(LandlockTest, CreateRulesetUnsupportedNetAttr)
{
	int version = syscall(__NR_landlock_create_ruleset, nullptr, 0,
			      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	if (version < 4) {
		struct landlock_ruleset_attr attr_net = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
			.handled_access_net =
				1, // LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
			.scoped = 0,
		};
		EXPECT_THAT(syscall(__NR_landlock_create_ruleset, &attr_net,
				    sizeof(attr_net), 0),
			    SyscallFailsWithErrno(EINVAL));
	} else {
		struct landlock_ruleset_attr attr_net = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
			.handled_access_net = 1,
			.scoped = 0,
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset,
					 &attr_net, sizeof(attr_net), 0);
		ASSERT_GE(ruleset_fd, 0);
		close(ruleset_fd);
	}
}

TEST_F(LandlockTest, CreateRulesetUnsupportedScopedAttr)
{
	int version = syscall(__NR_landlock_create_ruleset, nullptr, 0,
			      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	if (version < 6) {
		struct landlock_ruleset_attr attr_scoped = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
			.handled_access_net = 0,
			.scoped =
				1, // LANDLOCK_SCOPED_ABSTRACT_UNIX_SOCKET (1ULL << 0)
		};
		EXPECT_THAT(syscall(__NR_landlock_create_ruleset, &attr_scoped,
				    sizeof(attr_scoped), 0),
			    SyscallFailsWithErrno(EINVAL));
	} else {
		struct landlock_ruleset_attr attr_scoped = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
			.handled_access_net = 0,
			.scoped = 1,
		};
		int ruleset_fd = syscall(__NR_landlock_create_ruleset,
					 &attr_scoped, sizeof(attr_scoped), 0);
		ASSERT_GE(ruleset_fd, 0);
		close(ruleset_fd);
	}
}

TEST_F(LandlockTest, CreateRulesetUnsupportedFSAccess)
{
	int version = syscall(__NR_landlock_create_ruleset, nullptr, 0,
			      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
				     LANDLOCK_ACCESS_FS_REFER,
		.handled_access_net = 0,
		.scoped = 0,
	};

	if (version < 2) {
		EXPECT_THAT(syscall(__NR_landlock_create_ruleset, &attr,
				    sizeof(attr), 0),
			    SyscallFailsWithErrno(EINVAL));
	} else {
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		close(ruleset_fd);
	}
}

TEST_F(LandlockTest, CreateRulesetUnsupportedFSAccessSize8)
{
	int version = syscall(__NR_landlock_create_ruleset, nullptr, 0,
			      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr_v1 {
		uint64_t handled_access_fs;
	};
	struct landlock_ruleset_attr_v1 attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
				     LANDLOCK_ACCESS_FS_REFER,
	};

	if (version < 2) {
		EXPECT_THAT(syscall(__NR_landlock_create_ruleset, &attr,
				    sizeof(attr), 0),
			    SyscallFailsWithErrno(EINVAL));
	} else {
		int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
		ASSERT_GE(ruleset_fd, 0);
		close(ruleset_fd);
	}
}

TEST_F(LandlockTest, CreateRulesetInvalidFSAccessBits)
{
	struct landlock_ruleset_attr attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
				     (1ULL << 60),
		.handled_access_net = 0,
		.scoped = 0,
	};
	EXPECT_THAT(syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr),
			    0),
		    SyscallFailsWithErrno(EINVAL));
}

} // namespace
} // namespace testing
} // namespace gvisor
