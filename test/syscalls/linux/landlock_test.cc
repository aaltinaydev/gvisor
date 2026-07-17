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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <condition_variable>
#include <mutex>
#include <thread>

#include "gtest/gtest.h"
#include "test/util/capability_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

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

// v2
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
// v3
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
// v5
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)

enum landlock_rule_type {
	LANDLOCK_RULE_PATH_BENEATH = 1,
};

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

inline int landlock_create_ruleset(const landlock_ruleset_attr *attr,
				   size_t size, uint32_t flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

inline int landlock_add_rule(int ruleset_fd, landlock_rule_type rule_type,
			     const void *rule_attr, uint32_t flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
		       flags);
}

inline int landlock_restrict_self(int ruleset_fd, uint32_t flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

bool IsLandlockSupported()
{
	int fd = landlock_create_ruleset(nullptr, 0,
					 LANDLOCK_CREATE_RULESET_VERSION);
	if (fd < 0) {
		if (errno == ENOSYS || errno == EOPNOTSUPP) {
			return false;
		}
	}
	return true;
}

uint64_t GetSupportedFSAttributes(int version)
{
	uint64_t mask = 0;
	if (version >= 1) {
		mask |= (1ULL << 13) - 1; // v1 FS attributes
	}
	if (version >= 2) {
		mask |= LANDLOCK_ACCESS_FS_REFER;
	}
	if (version >= 3) {
		mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
	}
	if (version >= 5) {
		mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
	}
	return mask;
}

class LandlockTest : public ::testing::Test {
    protected:
	void SetUp() override
	{
		if (!IsLandlockSupported()) {
			GTEST_SKIP() << "Landlock not supported by kernel";
		}
	}
};

TEST_F(LandlockTest, CreateRulesetVersionQuery)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);
}

TEST_F(LandlockTest, CreateRulesetInvalidFlags)
{
	EXPECT_THAT(landlock_create_ruleset(nullptr, 0, 1U << 31),
		    SyscallFailsWithErrno(EINVAL));
}

TEST_F(LandlockTest, CreateRulesetInvalidArgsForVersionQuery)
{
	struct landlock_ruleset_attr attr = { 0 };
	EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr),
					    LANDLOCK_CREATE_RULESET_VERSION),
		    SyscallFailsWithErrno(EINVAL));
	EXPECT_THAT(landlock_create_ruleset(nullptr, sizeof(attr),
					    LANDLOCK_CREATE_RULESET_VERSION),
		    SyscallFailsWithErrno(EINVAL));
}

TEST_F(LandlockTest, CreateRulesetNullAttr)
{
	EXPECT_THAT(landlock_create_ruleset(nullptr, 0, 0),
		    SyscallFailsWithErrno(EFAULT));
}

TEST_F(LandlockTest, CreateRulesetInvalidSize)
{
	struct landlock_ruleset_attr attr = { 0 };
	EXPECT_THAT(landlock_create_ruleset(&attr, 7, 0),
		    SyscallFailsWithErrno(EINVAL));
	EXPECT_THAT(landlock_create_ruleset(&attr, 4097, 0),
		    SyscallFailsWithErrno(E2BIG));
}

TEST_F(LandlockTest, CreateRulesetInvalidAccessBits)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = 1ULL << 60;
	EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
		    SyscallFailsWithErrno(EINVAL));

	if (version == 1) {
		attr.handled_access_fs = LANDLOCK_ACCESS_FS_REFER;
		EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
			    SyscallFailsWithErrno(EINVAL));
	}
}

TEST_F(LandlockTest, CreateRulesetSuccess)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = GetSupportedFSAttributes(version);

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	close(ruleset_fd);
}

TEST_F(LandlockTest, RestrictSelfValidationNoPrivs)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = GetSupportedFSAttributes(version);

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor fd(ruleset_fd);

	int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (nnp != 0) {
		GTEST_SKIP()
			<< "PR_SET_NO_NEW_PRIVS is already set, cannot test EPERM";
	}

	auto has_admin = HaveCapability(CAP_SYS_ADMIN);
	ASSERT_TRUE(has_admin.ok());

	if (has_admin.ValueOrDie()) {
		const DisableSave ds;
		AutoCapability cap(CAP_SYS_ADMIN, false);
		EXPECT_THAT(landlock_restrict_self(fd.get(), 0),
			    SyscallFailsWithErrno(EPERM));
		EXPECT_THAT(landlock_restrict_self(fd.get(), 1U << 31),
			    SyscallFailsWithErrno(EPERM));
	} else {
		EXPECT_THAT(landlock_restrict_self(fd.get(), 0),
			    SyscallFailsWithErrno(EPERM));
		EXPECT_THAT(landlock_restrict_self(fd.get(), 1U << 31),
			    SyscallFailsWithErrno(EPERM));
	}
}

TEST_F(LandlockTest, RestrictSelfValidationWithNNP)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = GetSupportedFSAttributes(version);

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor fd(ruleset_fd);

	TempPath tmp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
	int opath_fd = open(tmp_file.path().c_str(), O_PATH);
	ASSERT_GE(opath_fd, 0);
	FileDescriptor opath_desc(opath_fd);

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}

		if (landlock_restrict_self(fd.get(), 1U << 31) >= 0) {
			fprintf(stderr,
				"landlock_restrict_self with invalid flags succeeded unexpectedly\n");
			_exit(2);
		}
		if (errno != EINVAL) {
			fprintf(stderr,
				"landlock_restrict_self with invalid flags failed with wrong "
				"errno: %d (expected EINVAL)\n",
				errno);
			_exit(3);
		}

		if (landlock_restrict_self(-1, 0) >= 0) {
			fprintf(stderr,
				"landlock_restrict_self(-1) succeeded unexpectedly\n");
			_exit(4);
		}
		if (errno != EBADF) {
			fprintf(stderr,
				"landlock_restrict_self(-1) failed with wrong errno: %d "
				"(expected EBADF)\n",
				errno);
			_exit(5);
		}

		int normal_fd = open("/dev/null", O_RDONLY);
		if (normal_fd < 0) {
			perror("open(/dev/null)");
			_exit(6);
		}
		if (landlock_restrict_self(normal_fd, 0) >= 0) {
			fprintf(stderr,
				"landlock_restrict_self(normal_fd) succeeded unexpectedly\n");
			close(normal_fd);
			_exit(7);
		}
		if (errno != EBADFD) {
			fprintf(stderr,
				"landlock_restrict_self(normal_fd) failed with wrong errno: %d "
				"(expected EBADFD)\n",
				errno);
			close(normal_fd);
			_exit(8);
		}
		close(normal_fd);

		if (landlock_restrict_self(opath_desc.get(), 0) >= 0) {
			fprintf(stderr,
				"landlock_restrict_self(opath_fd) succeeded unexpectedly\n");
			_exit(9);
		}
		if (errno != EBADF) {
			fprintf(stderr,
				"landlock_restrict_self(opath_fd) failed with wrong errno: %d "
				"(expected EBADF)\n",
				errno);
			_exit(10);
		}

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(LandlockTest, RestrictSelfSuccessWithNNP)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = GetSupportedFSAttributes(version);

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor fd(ruleset_fd);

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}
		if (landlock_restrict_self(fd.get(), 0) < 0) {
			perror("landlock_restrict_self");
			_exit(2);
		}
		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(LandlockTest, RestrictSelfSuccessWithCapSysAdmin)
{
	auto has_admin = HaveCapability(CAP_SYS_ADMIN);
	ASSERT_TRUE(has_admin.ok());
	if (!has_admin.ValueOrDie()) {
		GTEST_SKIP() << "Test requires CAP_SYS_ADMIN";
	}

	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = GetSupportedFSAttributes(version);

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor fd(ruleset_fd);

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (landlock_restrict_self(fd.get(), 0) < 0) {
			perror("landlock_restrict_self with CAP_SYS_ADMIN");
			_exit(1);
		}
		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(LandlockTest, AddRuleValidation)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor fd(ruleset_fd);

	TempPath tmp_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
	int file_fd = open(tmp_file.path().c_str(), O_PATH);
	ASSERT_GE(file_fd, 0);
	FileDescriptor f_fd(file_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = f_fd.get();
	rule_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;

	EXPECT_THAT(landlock_add_rule(fd.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	EXPECT_THAT(landlock_add_rule(-1, LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallFailsWithErrno(EBADF));

	EXPECT_THAT(landlock_add_rule(f_fd.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallFailsWithErrno(EBADF));

	{
		int normal_file_fd = open(tmp_file.path().c_str(), O_RDONLY);
		ASSERT_GE(normal_file_fd, 0);
		FileDescriptor normal_f_desc(normal_file_fd);
		EXPECT_THAT(landlock_add_rule(normal_f_desc.get(),
					      LANDLOCK_RULE_PATH_BENEATH,
					      &rule_attr, 0),
			    SyscallFailsWithErrno(EBADFD));
	}

	EXPECT_THAT(landlock_add_rule(fd.get(),
				      static_cast<enum landlock_rule_type>(0),
				      &rule_attr, 0),
		    SyscallFailsWithErrno(EINVAL));
	EXPECT_THAT(landlock_add_rule(fd.get(),
				      static_cast<enum landlock_rule_type>(999),
				      &rule_attr, 0),
		    SyscallFailsWithErrno(EINVAL));

	EXPECT_THAT(landlock_add_rule(fd.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 1),
		    SyscallFailsWithErrno(EINVAL));

	struct landlock_path_beneath_attr invalid_rule_attr = { 0 };
	invalid_rule_attr.parent_fd = f_fd.get();
	invalid_rule_attr.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE;
	EXPECT_THAT(landlock_add_rule(fd.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &invalid_rule_attr, 0),
		    SyscallFailsWithErrno(EINVAL));

	struct landlock_path_beneath_attr empty_rule_attr = { 0 };
	empty_rule_attr.parent_fd = f_fd.get();
	empty_rule_attr.allowed_access = 0;
	EXPECT_THAT(landlock_add_rule(fd.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &empty_rule_attr, 0),
		    SyscallFailsWithErrno(ENOMSG));

	struct landlock_path_beneath_attr invalid_parent_attr = { 0 };
	invalid_parent_attr.parent_fd = -1;
	invalid_parent_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
	EXPECT_THAT(landlock_add_rule(fd.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &invalid_parent_attr, 0),
		    SyscallFailsWithErrno(EBADF));

	int pipe_fds[2];
	ASSERT_EQ(pipe(pipe_fds), 0);
	FileDescriptor pipe_r(pipe_fds[0]);
	FileDescriptor pipe_w(pipe_fds[1]);
	struct landlock_path_beneath_attr pipe_parent_attr = { 0 };
	pipe_parent_attr.parent_fd = pipe_r.get();
	pipe_parent_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
	EXPECT_THAT(landlock_add_rule(fd.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &pipe_parent_attr, 0),
		    SyscallFailsWithErrno(EBADFD));
}

TEST_F(LandlockTest, FunctionalWriteRestriction)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_WRITE_FILE |
				  LANDLOCK_ACCESS_FS_MAKE_REG;

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor ruleset(ruleset_fd);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	std::string dir_allowed = JoinPath(parent_dir.path(), "allowed");
	std::string dir_denied = JoinPath(parent_dir.path(), "denied");
	ASSERT_THAT(mkdir(dir_allowed.c_str(), 0755), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir_denied.c_str(), 0755), SyscallSucceeds());

	auto file_allowed_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_allowed, "hello", 0644));
	std::string file_allowed = file_allowed_temp.path();

	auto file_denied_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_denied, "world", 0644));
	std::string file_denied = file_denied_temp.path();

	int dir_allowed_fd = open(dir_allowed.c_str(), O_PATH);
	ASSERT_GE(dir_allowed_fd, 0);
	FileDescriptor dir_allowed_desc(dir_allowed_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = dir_allowed_desc.get();
	rule_attr.allowed_access = handled_access;

	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}
		if (landlock_restrict_self(ruleset.get(), 0) < 0) {
			perror("landlock_restrict_self");
			_exit(2);
		}

		std::string new_file_allowed = JoinPath(dir_allowed, "new.txt");
		int fd = open(new_file_allowed.c_str(), O_CREAT | O_WRONLY,
			      0644);
		if (fd < 0) {
			perror("open(new_file_allowed) failed");
			_exit(3);
		}
		close(fd);

		fd = open(file_allowed.c_str(), O_WRONLY);
		if (fd < 0) {
			perror("open(file_allowed) failed");
			_exit(4);
		}
		close(fd);

		std::string new_file_denied = JoinPath(dir_denied, "new.txt");
		fd = open(new_file_denied.c_str(), O_CREAT | O_WRONLY, 0644);
		if (fd >= 0) {
			fprintf(stderr,
				"open(new_file_denied) succeeded unexpectedly\n");
			close(fd);
			_exit(5);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"open(new_file_denied) failed with wrong errno: %d\n",
				errno);
			_exit(6);
		}

		fd = open(file_denied.c_str(), O_WRONLY);
		if (fd >= 0) {
			fprintf(stderr,
				"open(file_denied) succeeded unexpectedly\n");
			close(fd);
			_exit(7);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"open(file_denied) failed with wrong errno: %d\n",
				errno);
			_exit(8);
		}

		std::string new_file_parent =
			JoinPath(parent_dir.path(), "new.txt");
		fd = open(new_file_parent.c_str(), O_CREAT | O_WRONLY, 0644);
		if (fd >= 0) {
			fprintf(stderr,
				"open(new_file_parent) succeeded unexpectedly\n");
			close(fd);
			_exit(9);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"open(new_file_parent) failed with wrong errno: %d\n",
				errno);
			_exit(10);
		}

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);

	// Invariance check: Parent must not be restricted.
	std::string parent_test_file = JoinPath(dir_denied, "parent_test.txt");
	int parent_fd =
		open(parent_test_file.c_str(), O_CREAT | O_WRONLY, 0644);
	EXPECT_THAT(parent_fd, SyscallSucceeds());
	if (parent_fd >= 0) {
		close(parent_fd);
		unlink(parent_test_file.c_str());
	}
}

TEST_F(LandlockTest, FunctionalReadRestriction)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_READ_FILE |
				  LANDLOCK_ACCESS_FS_READ_DIR;

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor ruleset(ruleset_fd);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	std::string dir_allowed = JoinPath(parent_dir.path(), "allowed");
	std::string dir_denied = JoinPath(parent_dir.path(), "denied");
	ASSERT_THAT(mkdir(dir_allowed.c_str(), 0755), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir_denied.c_str(), 0755), SyscallSucceeds());

	auto file_allowed_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_allowed, "hello", 0644));
	std::string file_allowed = file_allowed_temp.path();

	auto file_denied_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_denied, "world", 0644));
	std::string file_denied = file_denied_temp.path();

	int dir_allowed_fd = open(dir_allowed.c_str(), O_PATH);
	ASSERT_GE(dir_allowed_fd, 0);
	FileDescriptor dir_allowed_desc(dir_allowed_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = dir_allowed_desc.get();
	rule_attr.allowed_access = handled_access;

	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}
		if (landlock_restrict_self(ruleset.get(), 0) < 0) {
			perror("landlock_restrict_self");
			_exit(2);
		}

		int fd = open(file_allowed.c_str(), O_RDONLY);
		if (fd < 0) {
			perror("open(file_allowed) failed");
			_exit(3);
		}
		char buf[10];
		if (read(fd, buf, sizeof(buf)) < 0) {
			perror("read(file_allowed) failed");
			close(fd);
			_exit(4);
		}
		close(fd);

		DIR *dir = opendir(dir_allowed.c_str());
		if (dir == nullptr) {
			perror("opendir(dir_allowed) failed");
			_exit(5);
		}
		struct dirent *entry = readdir(dir);
		if (entry == nullptr) {
			perror("readdir(dir_allowed) failed");
			closedir(dir);
			_exit(6);
		}
		closedir(dir);

		fd = open(file_denied.c_str(), O_RDONLY);
		if (fd >= 0) {
			fprintf(stderr,
				"open(file_denied) succeeded unexpectedly\n");
			close(fd);
			_exit(7);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"open(file_denied) failed with wrong errno: %d\n",
				errno);
			_exit(8);
		}

		dir = opendir(dir_denied.c_str());
		if (dir != nullptr) {
			fprintf(stderr,
				"opendir(dir_denied) succeeded unexpectedly\n");
			closedir(dir);
			_exit(9);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"opendir(dir_denied) failed with wrong errno: %d\n",
				errno);
			_exit(10);
		}

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);

	// Invariance check: Parent must still be able to read denied dir.
	int parent_fd = open(file_denied.c_str(), O_RDONLY);
	EXPECT_THAT(parent_fd, SyscallSucceeds());
	if (parent_fd >= 0) {
		close(parent_fd);
	}
}

TEST_F(LandlockTest, FunctionalNestedRulesets)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_WRITE_FILE;

	struct landlock_ruleset_attr attr1 = { 0 };
	attr1.handled_access_fs = handled_access;
	int ruleset_fd1 = landlock_create_ruleset(&attr1, sizeof(attr1), 0);
	ASSERT_THAT(ruleset_fd1, SyscallSucceeds());
	FileDescriptor ruleset1(ruleset_fd1);

	struct landlock_ruleset_attr attr2 = { 0 };
	attr2.handled_access_fs = handled_access;
	int ruleset_fd2 = landlock_create_ruleset(&attr2, sizeof(attr2), 0);
	ASSERT_THAT(ruleset_fd2, SyscallSucceeds());
	FileDescriptor ruleset2(ruleset_fd2);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	std::string dir_a = JoinPath(parent_dir.path(), "dir_a");
	std::string dir_b = JoinPath(parent_dir.path(), "dir_b");
	ASSERT_THAT(mkdir(dir_a.c_str(), 0755), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir_b.c_str(), 0755), SyscallSucceeds());

	auto file_a_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_a, "a", 0644));
	std::string file_a = file_a_temp.path();

	auto file_b_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_b, "b", 0644));
	std::string file_b = file_b_temp.path();

	int dir_a_fd = open(dir_a.c_str(), O_PATH);
	ASSERT_GE(dir_a_fd, 0);
	FileDescriptor dir_a_desc(dir_a_fd);

	int dir_b_fd = open(dir_b.c_str(), O_PATH);
	ASSERT_GE(dir_b_fd, 0);
	FileDescriptor dir_b_desc(dir_b_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = dir_a_desc.get();
	rule_attr.allowed_access = handled_access;
	ASSERT_THAT(landlock_add_rule(ruleset1.get(),
				      LANDLOCK_RULE_PATH_BENEATH, &rule_attr,
				      0),
		    SyscallSucceeds());

	rule_attr.parent_fd = dir_b_desc.get();
	ASSERT_THAT(landlock_add_rule(ruleset1.get(),
				      LANDLOCK_RULE_PATH_BENEATH, &rule_attr,
				      0),
		    SyscallSucceeds());

	rule_attr.parent_fd = dir_a_desc.get();
	ASSERT_THAT(landlock_add_rule(ruleset2.get(),
				      LANDLOCK_RULE_PATH_BENEATH, &rule_attr,
				      0),
		    SyscallSucceeds());

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}

		if (landlock_restrict_self(ruleset1.get(), 0) < 0) {
			perror("landlock_restrict_self 1");
			_exit(2);
		}

		int fd = open(file_a.c_str(), O_WRONLY);
		if (fd < 0) {
			perror("open(file_a) after ruleset 1 failed");
			_exit(3);
		}
		close(fd);

		fd = open(file_b.c_str(), O_WRONLY);
		if (fd < 0) {
			perror("open(file_b) after ruleset 1 failed");
			_exit(4);
		}
		close(fd);

		if (landlock_restrict_self(ruleset2.get(), 0) < 0) {
			perror("landlock_restrict_self 2");
			_exit(5);
		}

		fd = open(file_a.c_str(), O_WRONLY);
		if (fd < 0) {
			perror("open(file_a) after ruleset 2 failed");
			_exit(6);
		}
		close(fd);

		fd = open(file_b.c_str(), O_WRONLY);
		if (fd >= 0) {
			fprintf(stderr,
				"open(file_b) after ruleset 2 succeeded unexpectedly\n");
			close(fd);
			_exit(7);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"open(file_b) after ruleset 2 failed with wrong errno: %d\n",
				errno);
			_exit(8);
		}

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(LandlockTest, CrossDirectoryLinkRenameDenied)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_WRITE_FILE;

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor ruleset(ruleset_fd);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	std::string dir_a = JoinPath(parent_dir.path(), "dir_a");
	std::string dir_b = JoinPath(parent_dir.path(), "dir_b");
	ASSERT_THAT(mkdir(dir_a.c_str(), 0755), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir_b.c_str(), 0755), SyscallSucceeds());

	auto file_a_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_a, "hello", 0644));
	std::string file_a = file_a_temp.path();
	std::string file_b_link = JoinPath(dir_b, "file_link");
	std::string file_b_rename = JoinPath(dir_b, "file_rename");

	int dir_a_fd = open(dir_a.c_str(), O_PATH);
	ASSERT_GE(dir_a_fd, 0);
	FileDescriptor dir_a_desc(dir_a_fd);

	int dir_b_fd = open(dir_b.c_str(), O_PATH);
	ASSERT_GE(dir_b_fd, 0);
	FileDescriptor dir_b_desc(dir_b_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = dir_a_desc.get();
	rule_attr.allowed_access = handled_access;
	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	rule_attr.parent_fd = dir_b_desc.get();
	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}
		if (landlock_restrict_self(ruleset.get(), 0) < 0) {
			perror("landlock_restrict_self");
			_exit(2);
		}

		if (link(file_a.c_str(), file_b_link.c_str()) >= 0) {
			fprintf(stderr,
				"link cross-dir succeeded unexpectedly\n");
			_exit(3);
		}
		if (errno != EXDEV) {
			fprintf(stderr,
				"link cross-dir failed with wrong errno: %d (expected EXDEV)\n",
				errno);
			_exit(4);
		}

		if (rename(file_a.c_str(), file_b_rename.c_str()) >= 0) {
			fprintf(stderr,
				"rename cross-dir succeeded unexpectedly\n");
			_exit(5);
		}
		if (errno != EXDEV) {
			fprintf(stderr,
				"rename cross-dir failed with wrong errno: %d (expected EXDEV)\n",
				errno);
			_exit(6);
		}

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(LandlockTest, SameDirectoryLinkPermissions)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_MAKE_REG;

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor ruleset(ruleset_fd);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	std::string dir_allowed = JoinPath(parent_dir.path(), "allowed");
	std::string dir_denied = JoinPath(parent_dir.path(), "denied");
	ASSERT_THAT(mkdir(dir_allowed.c_str(), 0755), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir_denied.c_str(), 0755), SyscallSucceeds());

	auto file_allowed_src_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_allowed, "src", 0644));
	std::string file_allowed_src = file_allowed_src_temp.path();
	std::string file_allowed_dst = JoinPath(dir_allowed, "dst");

	auto file_denied_src_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_denied, "src", 0644));
	std::string file_denied_src = file_denied_src_temp.path();
	std::string file_denied_dst = JoinPath(dir_denied, "dst");

	int dir_allowed_fd = open(dir_allowed.c_str(), O_PATH);
	ASSERT_GE(dir_allowed_fd, 0);
	FileDescriptor dir_allowed_desc(dir_allowed_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = dir_allowed_desc.get();
	rule_attr.allowed_access = handled_access;
	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}
		if (landlock_restrict_self(ruleset.get(), 0) < 0) {
			perror("landlock_restrict_self");
			_exit(2);
		}

		if (link(file_allowed_src.c_str(), file_allowed_dst.c_str()) <
		    0) {
			perror("link in allowed dir failed");
			_exit(3);
		}

		if (link(file_denied_src.c_str(), file_denied_dst.c_str()) >=
		    0) {
			fprintf(stderr,
				"link in denied dir succeeded unexpectedly\n");
			_exit(4);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"link in denied dir failed with wrong errno: %d (expected EACCES)\n",
				errno);
			_exit(5);
		}

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(LandlockTest, SameDirectoryRenamePermissions)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_REMOVE_FILE |
				  LANDLOCK_ACCESS_FS_MAKE_REG;

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor ruleset(ruleset_fd);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

	std::string dir_allowed = JoinPath(parent_dir.path(), "allowed");
	std::string dir_no_remove = JoinPath(parent_dir.path(), "no_remove");
	std::string dir_no_make = JoinPath(parent_dir.path(), "no_make");

	ASSERT_THAT(mkdir(dir_allowed.c_str(), 0755), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir_no_remove.c_str(), 0755), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir_no_make.c_str(), 0755), SyscallSucceeds());

	auto file_allowed_src_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_allowed, "src", 0644));
	std::string file_allowed_src = file_allowed_src_temp.path();
	std::string file_allowed_dst = JoinPath(dir_allowed, "dst");

	auto file_no_remove_src_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_no_remove, "src", 0644));
	std::string file_no_remove_src = file_no_remove_src_temp.path();
	std::string file_no_remove_dst = JoinPath(dir_no_remove, "dst");

	auto file_no_make_src_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_no_make, "src", 0644));
	std::string file_no_make_src = file_no_make_src_temp.path();
	std::string file_no_make_dst = JoinPath(dir_no_make, "dst");

	int dir_allowed_fd = open(dir_allowed.c_str(), O_PATH);
	ASSERT_GE(dir_allowed_fd, 0);
	FileDescriptor dir_allowed_desc(dir_allowed_fd);

	int dir_no_remove_fd = open(dir_no_remove.c_str(), O_PATH);
	ASSERT_GE(dir_no_remove_fd, 0);
	FileDescriptor dir_no_remove_desc(dir_no_remove_fd);

	int dir_no_make_fd = open(dir_no_make.c_str(), O_PATH);
	ASSERT_GE(dir_no_make_fd, 0);
	FileDescriptor dir_no_make_desc(dir_no_make_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = dir_allowed_desc.get();
	rule_attr.allowed_access = handled_access;
	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	rule_attr.parent_fd = dir_no_remove_desc.get();
	rule_attr.allowed_access = LANDLOCK_ACCESS_FS_MAKE_REG;
	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	rule_attr.parent_fd = dir_no_make_desc.get();
	rule_attr.allowed_access = LANDLOCK_ACCESS_FS_REMOVE_FILE;
	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}
		if (landlock_restrict_self(ruleset.get(), 0) < 0) {
			perror("landlock_restrict_self");
			_exit(2);
		}

		if (rename(file_allowed_src.c_str(), file_allowed_dst.c_str()) <
		    0) {
			perror("rename in allowed dir failed");
			_exit(3);
		}

		if (rename(file_no_remove_src.c_str(),
			   file_no_remove_dst.c_str()) >= 0) {
			fprintf(stderr,
				"rename in dir_no_remove succeeded unexpectedly\n");
			_exit(4);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"rename in dir_no_remove failed with wrong errno: %d (expected "
				"EACCES)\n",
				errno);
			_exit(5);
		}

		if (rename(file_no_make_src.c_str(),
			   file_no_make_dst.c_str()) >= 0) {
			fprintf(stderr,
				"rename in dir_no_make succeeded unexpectedly\n");
			_exit(6);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"rename in dir_no_make failed with wrong errno: %d (expected "
				"EACCES)\n",
				errno);
			_exit(7);
		}

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(LandlockTest, OpenAtCreatePermissions)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_MAKE_REG |
				  LANDLOCK_ACCESS_FS_WRITE_FILE;

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor ruleset(ruleset_fd);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	std::string dir = parent_dir.path();

	std::string file_new = JoinPath(dir, "new_file");
	std::string file_existing = JoinPath(dir, "existing_file");

	int fd = open(file_existing.c_str(), O_CREAT | O_WRONLY, 0644);
	ASSERT_GE(fd, 0);
	close(fd);

	int dir_fd = open(dir.c_str(), O_PATH);
	ASSERT_GE(dir_fd, 0);
	FileDescriptor dir_desc(dir_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = dir_desc.get();
	rule_attr.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE;
	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}
		if (landlock_restrict_self(ruleset.get(), 0) < 0) {
			perror("landlock_restrict_self");
			_exit(2);
		}

		int fd_new = open(file_new.c_str(), O_CREAT | O_WRONLY, 0644);
		if (fd_new >= 0) {
			fprintf(stderr,
				"open(O_CREAT) for non-existing file succeeded unexpectedly\n");
			close(fd_new);
			_exit(3);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"open(O_CREAT) failed with wrong errno: %d (expected EACCES)\n",
				errno);
			_exit(4);
		}

		int fd_exist = open(file_existing.c_str(), O_WRONLY);
		if (fd_exist < 0) {
			perror("open(O_WRONLY) for existing file failed");
			_exit(5);
		}
		close(fd_exist);

		fd_exist =
			open(file_existing.c_str(), O_CREAT | O_WRONLY, 0644);
		if (fd_exist < 0) {
			perror("open(O_CREAT | O_WRONLY) for existing file failed");
			_exit(6);
		}
		close(fd_exist);

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(LandlockTest, AddRuleWithRulesetFDAsParent)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor fd(ruleset_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = fd.get(); // Use ruleset FD as parent!
	rule_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;

	EXPECT_THAT(landlock_add_rule(fd.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallFailsWithErrno(EBADFD));
}

TEST_F(LandlockTest, RestrictSelfThreadIsolation)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_WRITE_FILE;
	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor ruleset(ruleset_fd);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	std::string dir_allowed = JoinPath(parent_dir.path(), "allowed");
	std::string dir_denied = JoinPath(parent_dir.path(), "denied");
	ASSERT_THAT(mkdir(dir_allowed.c_str(), 0755), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir_denied.c_str(), 0755), SyscallSucceeds());

	auto file_allowed_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_allowed, "hello", 0644));
	std::string file_allowed = file_allowed_temp.path();

	auto file_denied_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_denied, "world", 0644));
	std::string file_denied = file_denied_temp.path();

	int dir_allowed_fd = open(dir_allowed.c_str(), O_PATH);
	ASSERT_GE(dir_allowed_fd, 0);
	FileDescriptor dir_allowed_desc(dir_allowed_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = dir_allowed_desc.get();
	rule_attr.allowed_access = handled_access;

	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	bool has_admin_bool = false;
	auto has_admin = HaveCapability(CAP_SYS_ADMIN);
	ASSERT_TRUE(has_admin.ok());
	has_admin_bool = has_admin.ValueOrDie();

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		std::mutex mu;
		std::condition_variable cv;
		bool thread_a_ready = false;
		bool main_thread_restricted = false;
		bool thread_a_done = false;
		int thread_a_write_errno = 0;

		// Spawn Thread A (sibling thread, should remain unrestricted).
		ScopedThread thread_a([&]() {
			{
				std::unique_lock<std::mutex> lock(mu);
				thread_a_ready = true;
				cv.notify_all();
				cv.wait(lock,
					[&] { return main_thread_restricted; });
			}

			// Try to write to denied file.
			int fd = open(file_denied.c_str(), O_WRONLY);
			if (fd >= 0) {
				close(fd);
				thread_a_write_errno = 0;
			} else {
				thread_a_write_errno = errno;
			}

			{
				std::unique_lock<std::mutex> lock(mu);
				thread_a_done = true;
				cv.notify_all();
			}
		});

		// Wait for Thread A to be ready.
		{
			std::unique_lock<std::mutex> lock(mu);
			cv.wait(lock, [&] { return thread_a_ready; });
		}

		// Main thread restricts itself.
		if (!has_admin_bool) {
			if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
				perror("prctl(PR_SET_NO_NEW_PRIVS)");
				_exit(2);
			}
		}

		if (landlock_restrict_self(ruleset.get(), 0) < 0) {
			perror("landlock_restrict_self");
			_exit(3);
		}

		// Signal Thread A to proceed.
		{
			std::unique_lock<std::mutex> lock(mu);
			main_thread_restricted = true;
			cv.notify_all();
		}

		// Main thread tries to write to denied file -> should fail with EACCES.
		int fd_main = open(file_denied.c_str(), O_WRONLY);
		if (fd_main >= 0) {
			fprintf(stderr,
				"Main thread write succeeded unexpectedly\n");
			close(fd_main);
			_exit(4);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"Main thread write failed with wrong errno: %d (expected EACCES)\n",
				errno);
			_exit(5);
		}

		// Wait for Thread A to finish.
		{
			std::unique_lock<std::mutex> lock(mu);
			cv.wait(lock, [&] { return thread_a_done; });
		}

		thread_a.Join();

		// Thread A should have succeeded (errno == 0).
		if (thread_a_write_errno != 0) {
			fprintf(stderr,
				"Thread A failed to write with errno: %s\n",
				strerror(thread_a_write_errno));
			_exit(6);
		}

		// Spawn Thread B (spawned AFTER restriction, should inherit restriction).
		int thread_b_write_errno = 0;
		{
			ScopedThread thread_b([&]() {
				int fd = open(file_denied.c_str(), O_WRONLY);
				if (fd >= 0) {
					close(fd);
					thread_b_write_errno = 0;
				} else {
					thread_b_write_errno = errno;
				}
			});
		}

		// Thread B should have failed with EACCES.
		if (thread_b_write_errno != EACCES) {
			fprintf(stderr,
				"Thread B failed with wrong errno: %d (expected EACCES)\n",
				thread_b_write_errno);
			_exit(7);
		}

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}
TEST_F(LandlockTest, CreateRulesetRejectsNetAndScoped)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;

	if (version < 4) {
		// LANDLOCK_ACCESS_NET_BIND_TCP is (1ULL << 0)
		attr.handled_access_net = 1ULL << 0;
		EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
			    SyscallFailsWithErrno(EINVAL));
		attr.handled_access_net = 0;
	}

	if (version < 6) {
		// LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET is (1ULL << 0)
		attr.scoped = 1ULL << 0;
		EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
			    SyscallFailsWithErrno(EINVAL));
	}
}

TEST_F(LandlockTest, MaxLayersLimit)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor ruleset(ruleset_fd);

	TempPath tmp_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	int dir_fd = open(tmp_dir.path().c_str(), O_PATH);
	ASSERT_GE(dir_fd, 0);
	FileDescriptor dir_desc(dir_fd);

	struct landlock_path_beneath_attr rule_attr = { 0 };
	rule_attr.parent_fd = dir_desc.get();
	rule_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;

	ASSERT_THAT(landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH,
				      &rule_attr, 0),
		    SyscallSucceeds());

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}

		for (int i = 0; i < 16; ++i) {
			if (landlock_restrict_self(ruleset.get(), 0) < 0) {
				perror("landlock_restrict_self failed before limit");
				_exit(2 + i);
			}
		}

		if (landlock_restrict_self(ruleset.get(), 0) >= 0) {
			fprintf(stderr,
				"17th landlock_restrict_self succeeded unexpectedly\n");
			_exit(20);
		}
		if (errno != E2BIG) {
			fprintf(stderr,
				"17th landlock_restrict_self failed with wrong errno: %d "
				"(expected E2BIG)\n",
				errno);
			_exit(21);
		}

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(LandlockTest, LinkRenameErrorPrioritization)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_MAKE_REG |
				  LANDLOCK_ACCESS_FS_REMOVE_FILE;

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	// Ruleset 1: Deny all (no rules added)
	int ruleset_fd1 = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd1, SyscallSucceeds());
	FileDescriptor ruleset1(ruleset_fd1);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	std::string dir_a = JoinPath(parent_dir.path(), "dir_a");
	std::string dir_b = JoinPath(parent_dir.path(), "dir_b");
	ASSERT_THAT(mkdir(dir_a.c_str(), 0755), SyscallSucceeds());
	ASSERT_THAT(mkdir(dir_b.c_str(), 0755), SyscallSucceeds());

	int dir_a_fd = open(dir_a.c_str(), O_PATH);
	ASSERT_GE(dir_a_fd, 0);
	FileDescriptor dir_a_desc(dir_a_fd);

	int dir_b_fd = open(dir_b.c_str(), O_PATH);
	ASSERT_GE(dir_b_fd, 0);
	FileDescriptor dir_b_desc(dir_b_fd);

	// Ruleset 2: Allow REMOVE_FILE on dir_a, deny MAKE_REG on dir_b
	int ruleset_fd2 = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd2, SyscallSucceeds());
	FileDescriptor ruleset2(ruleset_fd2);
	{
		struct landlock_path_beneath_attr rule_attr = { 0 };
		rule_attr.parent_fd = dir_a_desc.get();
		rule_attr.allowed_access = LANDLOCK_ACCESS_FS_REMOVE_FILE;
		ASSERT_THAT(landlock_add_rule(ruleset2.get(),
					      LANDLOCK_RULE_PATH_BENEATH,
					      &rule_attr, 0),
			    SyscallSucceeds());
	}

	// Ruleset 3: Deny REMOVE_FILE on dir_a, allow MAKE_REG on dir_b
	int ruleset_fd3 = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd3, SyscallSucceeds());
	FileDescriptor ruleset3(ruleset_fd3);
	{
		struct landlock_path_beneath_attr rule_attr = { 0 };
		rule_attr.parent_fd = dir_b_desc.get();
		rule_attr.allowed_access = LANDLOCK_ACCESS_FS_MAKE_REG;
		ASSERT_THAT(landlock_add_rule(ruleset3.get(),
					      LANDLOCK_RULE_PATH_BENEATH,
					      &rule_attr, 0),
			    SyscallSucceeds());
	}

	// Ruleset 4: Allow both (should result in EXDEV)
	int ruleset_fd4 = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd4, SyscallSucceeds());
	FileDescriptor ruleset4(ruleset_fd4);
	{
		struct landlock_path_beneath_attr rule_attr = { 0 };
		rule_attr.parent_fd = dir_a_desc.get();
		rule_attr.allowed_access = LANDLOCK_ACCESS_FS_REMOVE_FILE;
		ASSERT_THAT(landlock_add_rule(ruleset4.get(),
					      LANDLOCK_RULE_PATH_BENEATH,
					      &rule_attr, 0),
			    SyscallSucceeds());
		rule_attr.parent_fd = dir_b_desc.get();
		rule_attr.allowed_access = LANDLOCK_ACCESS_FS_MAKE_REG;
		ASSERT_THAT(landlock_add_rule(ruleset4.get(),
					      LANDLOCK_RULE_PATH_BENEATH,
					      &rule_attr, 0),
			    SyscallSucceeds());
	}

	// Helper to run test in child
	auto run_test = [&](int ruleset_fd, auto test_func) {
		auto file_a_temp = ASSERT_NO_ERRNO_AND_VALUE(
			TempPath::CreateFileWith(dir_a, "hello", 0644));
		std::string file_a = file_a_temp.path();
		std::string file_b_link = JoinPath(dir_b, "file_link");
		std::string file_b_rename = JoinPath(dir_b, "file_rename");

		pid_t pid = fork();
		ASSERT_GE(pid, 0);
		if (pid == 0) {
			if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
				perror("prctl(PR_SET_NO_NEW_PRIVS)");
				_exit(1);
			}
			if (landlock_restrict_self(ruleset_fd, 0) < 0) {
				perror("landlock_restrict_self");
				_exit(2);
			}
			int ret = test_func(file_a, file_b_link, file_b_rename);
			_exit(ret);
		}
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		EXPECT_EQ(WEXITSTATUS(status), 0);

		unlink(file_b_link.c_str());
		unlink(file_b_rename.c_str());
	};

	// Test 1: Ruleset 1 (Deny all) -> Link EACCES, Rename EACCES
	run_test(ruleset1.get(),
		 [](const std::string &src, const std::string &link_dst,
		    const std::string &rename_dst) {
			 if (link(src.c_str(), link_dst.c_str()) >= 0 ||
			     errno != EACCES) {
				 return 3;
			 }
			 if (rename(src.c_str(), rename_dst.c_str()) >= 0 ||
			     errno != EACCES) {
				 return 4;
			 }
			 return 0;
		 });

	// Test 2: Ruleset 2 (Allow src remove, deny dest make) -> Rename EACCES
	run_test(ruleset2.get(),
		 [](const std::string &src, const std::string &link_dst,
		    const std::string &rename_dst) {
			 if (rename(src.c_str(), rename_dst.c_str()) >= 0 ||
			     errno != EACCES) {
				 return 5;
			 }
			 return 0;
		 });

	// Test 3: Ruleset 3 (Deny src remove, allow dest make) -> Rename EACCES
	run_test(ruleset3.get(),
		 [](const std::string &src, const std::string &link_dst,
		    const std::string &rename_dst) {
			 if (rename(src.c_str(), rename_dst.c_str()) >= 0 ||
			     errno != EACCES) {
				 return 6;
			 }
			 return 0;
		 });

	// Test 4: Ruleset 4 (Allow both, deny REFER) -> Link EXDEV, Rename EXDEV
	run_test(ruleset4.get(),
		 [](const std::string &src, const std::string &link_dst,
		    const std::string &rename_dst) {
			 if (link(src.c_str(), link_dst.c_str()) >= 0 ||
			     errno != EXDEV) {
				 return 7;
			 }
			 if (rename(src.c_str(), rename_dst.c_str()) >= 0 ||
			     errno != EXDEV) {
				 return 8;
			 }
			 return 0;
		 });
}

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

TEST_F(LandlockTest, RenameExchangeSemantics)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_MAKE_REG |
				  LANDLOCK_ACCESS_FS_REMOVE_FILE;

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor ruleset(ruleset_fd);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	std::string dir_a = JoinPath(parent_dir.path(), "dir_a");
	ASSERT_THAT(mkdir(dir_a.c_str(), 0755), SyscallSucceeds());

	int dir_a_fd = open(dir_a.c_str(), O_PATH);
	ASSERT_GE(dir_a_fd, 0);
	FileDescriptor dir_a_desc(dir_a_fd);

	auto file_a_temp = ASSERT_NO_ERRNO_AND_VALUE(
		TempPath::CreateFileWith(dir_a, "hello", 0644));
	std::string file_a = file_a_temp.path();
	std::string file_b_nonexistent = JoinPath(dir_a, "nonexistent");

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}
		if (landlock_restrict_self(ruleset.get(), 0) < 0) {
			perror("landlock_restrict_self");
			_exit(2);
		}

		if (renameat2(AT_FDCWD, file_a.c_str(), AT_FDCWD,
			      file_b_nonexistent.c_str(),
			      RENAME_EXCHANGE) >= 0) {
			_exit(3);
		}
		if (errno != ENOENT) {
			_exit(4);
		}
		_exit(0);
	}
	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST_F(LandlockTest, RenameExchangeSameDir)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	uint64_t handled_access = LANDLOCK_ACCESS_FS_MAKE_REG |
				  LANDLOCK_ACCESS_FS_REMOVE_FILE;

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	int parent_fd = open(parent_dir.path().c_str(), O_PATH);
	ASSERT_GE(parent_fd, 0);
	FileDescriptor parent_desc(parent_fd);

	// Ruleset 1: Allow REMOVE but deny MAKE
	int ruleset_fd1 = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd1, SyscallSucceeds());
	FileDescriptor ruleset1(ruleset_fd1);
	{
		struct landlock_path_beneath_attr rule_attr = { 0 };
		rule_attr.parent_fd = parent_desc.get();
		rule_attr.allowed_access = LANDLOCK_ACCESS_FS_REMOVE_FILE;
		ASSERT_THAT(landlock_add_rule(ruleset1.get(),
					      LANDLOCK_RULE_PATH_BENEATH,
					      &rule_attr, 0),
			    SyscallSucceeds());
	}

	// Ruleset 2: Allow MAKE but deny REMOVE
	int ruleset_fd2 = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd2, SyscallSucceeds());
	FileDescriptor ruleset2(ruleset_fd2);
	{
		struct landlock_path_beneath_attr rule_attr = { 0 };
		rule_attr.parent_fd = parent_desc.get();
		rule_attr.allowed_access = LANDLOCK_ACCESS_FS_MAKE_REG;
		ASSERT_THAT(landlock_add_rule(ruleset2.get(),
					      LANDLOCK_RULE_PATH_BENEATH,
					      &rule_attr, 0),
			    SyscallSucceeds());
	}

	// Ruleset 3: Allow both
	int ruleset_fd3 = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd3, SyscallSucceeds());
	FileDescriptor ruleset3(ruleset_fd3);
	{
		struct landlock_path_beneath_attr rule_attr = { 0 };
		rule_attr.parent_fd = parent_desc.get();
		rule_attr.allowed_access = LANDLOCK_ACCESS_FS_MAKE_REG |
					   LANDLOCK_ACCESS_FS_REMOVE_FILE;
		ASSERT_THAT(landlock_add_rule(ruleset3.get(),
					      LANDLOCK_RULE_PATH_BENEATH,
					      &rule_attr, 0),
			    SyscallSucceeds());
	}

	auto run_test = [&](int ruleset_fd, auto test_func) {
		auto file_a_temp = ASSERT_NO_ERRNO_AND_VALUE(
			TempPath::CreateFileWith(parent_dir.path(), "hello",
						 0644));
		auto file_b_temp = ASSERT_NO_ERRNO_AND_VALUE(
			TempPath::CreateFileWith(parent_dir.path(), "world",
						 0644));
		std::string file_a = file_a_temp.path();
		std::string file_b = file_b_temp.path();

		pid_t pid = fork();
		ASSERT_GE(pid, 0);
		if (pid == 0) {
			if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
				perror("prctl(PR_SET_NO_NEW_PRIVS)");
				_exit(1);
			}
			if (landlock_restrict_self(ruleset_fd, 0) < 0) {
				perror("landlock_restrict_self");
				_exit(2);
			}
			int ret = test_func(file_a, file_b);
			_exit(ret);
		}
		int status;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		EXPECT_EQ(WEXITSTATUS(status), 0);
	};

	// Test 1: Allow REMOVE but deny MAKE -> should fail with EACCES
	run_test(ruleset1.get(),
		 [](const std::string &src, const std::string &dst) {
			 if (renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
				       dst.c_str(), RENAME_EXCHANGE) >= 0 ||
			     errno != EACCES) {
				 return 3;
			 }
			 return 0;
		 });

	// Test 2: Allow MAKE but deny REMOVE -> should fail with EACCES
	run_test(ruleset2.get(),
		 [](const std::string &src, const std::string &dst) {
			 if (renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
				       dst.c_str(), RENAME_EXCHANGE) >= 0 ||
			     errno != EACCES) {
				 return 4;
			 }
			 return 0;
		 });

	// Test 3: Allow both -> should succeed
	run_test(ruleset3.get(),
		 [](const std::string &src, const std::string &dst) {
			 if (renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
				       dst.c_str(), RENAME_EXCHANGE) < 0) {
				 return 5;
			 }
			 return 0;
		 });
}

TEST_F(LandlockTest, CleanupBypassesRemoveRestriction)
{
	int version = landlock_create_ruleset(nullptr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION);
	ASSERT_GE(version, 1);

	// We handle both MAKE_REG (to trigger failure on creation) and REMOVE_FILE
	// (to attempt to block cleanup).
	uint64_t handled_access = LANDLOCK_ACCESS_FS_MAKE_REG |
				  LANDLOCK_ACCESS_FS_REMOVE_FILE;

	struct landlock_ruleset_attr attr = { 0 };
	attr.handled_access_fs = handled_access;

	int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	ASSERT_THAT(ruleset_fd, SyscallSucceeds());
	FileDescriptor ruleset(ruleset_fd);

	TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
	std::string dir = parent_dir.path();
	std::string file_new = JoinPath(dir, "new_file");

	// We do NOT add any rules, so both MAKE_REG and REMOVE_FILE are blocked
	// for the parent_dir.

	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			_exit(1);
		}
		if (landlock_restrict_self(ruleset.get(), 0) < 0) {
			perror("landlock_restrict_self");
			_exit(2);
		}

		// Try to create a file. This should fail because MAKE_REG is blocked.
		// If the implementation is post-hoc, it will create the file and then
		// try to unlink it. The unlink should succeed even though REMOVE_FILE
		// is blocked, because cleanup should bypass Landlock.
		int fd = open(file_new.c_str(), O_CREAT | O_WRONLY, 0644);
		if (fd >= 0) {
			fprintf(stderr,
				"open(O_CREAT) succeeded unexpectedly\n");
			close(fd);
			_exit(3);
		}
		if (errno != EACCES) {
			fprintf(stderr,
				"open(O_CREAT) failed with wrong errno: %d (expected EACCES)\n",
				errno);
			_exit(4);
		}

		// Verify that the file does not exist.
		if (access(file_new.c_str(), F_OK) == 0) {
			fprintf(stderr,
				"file still exists after failed open (cleanup failed)\n");
			_exit(5);
		}
		if (errno != ENOENT) {
			fprintf(stderr,
				"access failed with wrong errno: %d (expected ENOENT)\n",
				errno);
			_exit(6);
		}

		_exit(0);
	}

	int status;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

} // namespace
} // namespace testing
} // namespace gvisor
