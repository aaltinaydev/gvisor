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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	// landlockABIVersion is the highest Landlock ABI version this
	// implementation supports, reported by landlock_create_ruleset(2) with
	// LANDLOCK_CREATE_RULESET_VERSION. It is a property of the implementation
	// rather than of the ABI, which is why it lives here rather than in
	// pkg/abi/linux; Linux likewise defines landlock_abi_version in
	// security/landlock/syscalls.c rather than in the UAPI header.
	landlockABIVersion = 1

	// landlockErrata is the bitmask of Landlock errata this implementation has
	// fixed, where erratum N is bit N-1, reported by landlock_create_ruleset(2)
	// with LANDLOCK_CREATE_RULESET_ERRATA. Erratum 3, on disconnected
	// directories, is the only one that applies to ABI 1, and the ancestor walk
	// implements it; the others apply to ABI versions above the one implemented
	// here, and Linux does not report those either.
	//
	// Matches Linux [security/landlock/errata/abi-1.h] and
	// [security/landlock/setup.c]:compute_errata()
	landlockErrata = 1 << (3 - 1)

	// landlockAccessFile is the set of access rights that apply to files rather
	// than directories, which a LANDLOCK_RULE_PATH_BENEATH rule on a
	// non-directory may not exceed. It is not part of the UAPI: the kernel
	// defines it as ACCESS_FILE, local to security/landlock/fs.c, and documents
	// the set under "The following access rights apply only to files" in
	// https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags.
	//
	// It mirrors ACCESS_FILE as of Linux 7.3, so it includes TRUNCATE (ABI v3),
	// IOCTL_DEV (ABI v5) and RESOLVE_UNIX (ABI v9). Those bits are unreachable
	// while only ABI v1 is implemented, because a ruleset's handled rights are
	// validated against LANDLOCK_ACCESS_FS_V1 and a rule's allowed rights are in
	// turn validated against the ruleset's.
	//
	// Matches Linux [security/landlock/fs.c]:ACCESS_FILE
	landlockAccessFile = linux.LANDLOCK_ACCESS_FS_EXECUTE |
		linux.LANDLOCK_ACCESS_FS_WRITE_FILE |
		linux.LANDLOCK_ACCESS_FS_READ_FILE |
		linux.LANDLOCK_ACCESS_FS_TRUNCATE |
		linux.LANDLOCK_ACCESS_FS_IOCTL_DEV |
		linux.LANDLOCK_ACCESS_FS_RESOLVE_UNIX
)

// LandlockCreateRuleset implements Linux syscall landlock_create_ruleset(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_create_ruleset()
func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	attrAddr := args[0].Pointer()
	size := args[1].SizeT()
	flags := args[2].Uint()

	if flags != 0 {
		if attrAddr != 0 || size != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_VERSION {
			return uintptr(landlockABIVersion), nil, nil
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_ERRATA {
			return uintptr(landlockErrata), nil, nil
		}
		return 0, nil, linuxerr.EINVAL
	}

	// To a kernel whose highest ABI is 1, landlock_ruleset_attr ends at
	// handled_access_fs: 8 bytes. A NULL attr is EFAULT before the size is
	// considered, then the size checks precede any access to the buffer.
	//
	// Matches Linux [security/landlock/syscalls.c]:copy_min_struct_from_user()
	const v1AttrSize = 8
	if attrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}
	if size < v1AttrSize {
		return 0, nil, linuxerr.EINVAL
	}
	if size > hostarch.PageSize {
		return 0, nil, linuxerr.E2BIG
	}

	// A longer struct than this ABI knows is acceptable only if the caller
	// asks for nothing in the part this ABI does not understand: any nonzero
	// byte past offset 8 is E2BIG, whether it lies in what a later ABI made
	// handled_access_net or scoped or beyond them, exactly as a v1-era kernel
	// treats the whole tail. The tail is checked before the head is copied.
	//
	// Matches Linux [lib/usercopy.c]:copy_struct_from_user()
	if size > v1AttrSize {
		extraBuf := make([]byte, size-v1AttrSize)
		if _, err := t.CopyInBytes(attrAddr+v1AttrSize, extraBuf); err != nil {
			return 0, nil, linuxerr.EFAULT
		}
		for _, b := range extraBuf {
			if b != 0 {
				return 0, nil, linuxerr.E2BIG
			}
		}
	}

	var handledAccessFS primitive.Uint64
	if _, err := handledAccessFS.CopyIn(t, attrAddr); err != nil {
		return 0, nil, linuxerr.EFAULT
	}

	if (uint64(handledAccessFS) &^ linux.LANDLOCK_ACCESS_FS_V1) != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if handledAccessFS == 0 {
		return 0, nil, linuxerr.ENOMSG
	}

	ruleset := vfs.NewLandlockRuleset(uint64(handledAccessFS))
	file, err := vfs.NewLandlockRulesetFD(t, t.Kernel().VFS(), ruleset)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)

	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}

// LandlockAddRule implements Linux syscall landlock_add_rule(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_add_rule()
func LandlockAddRule(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// Matches Linux [security/landlock/syscalls.c]:add_rule_path_beneath()
	rulesetFD := args[0].Int()
	ruleType := args[1].Uint()
	ruleAttrAddr := args[2].Pointer()
	flags := args[3].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	rulesetFile := t.GetFile(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)
	// get_ruleset_from_fd() takes the fd with fdget(), which treats an O_PATH
	// descriptor as though it were closed, so the answer is EBADF, not the
	// EBADFD of a descriptor that is open but not a ruleset.
	if rulesetFile.StatusFlags()&linux.O_PATH != 0 {
		return 0, nil, linuxerr.EBADF
	}

	ruleset, err := vfs.LandlockRulesetFromFD(rulesetFile, linux.O_WRONLY)
	if err != nil {
		return 0, nil, err
	}

	// The ruleset fd is validated before the rule type, so a call that gets both
	// wrong reports the fd, as sys_landlock_add_rule() resolves the fd before
	// the switch on rule_type.
	if ruleType != linux.LANDLOCK_RULE_PATH_BENEATH {
		return 0, nil, linuxerr.EINVAL
	}

	if ruleAttrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}

	var attr linux.LandlockPathBeneathAttr
	if _, err := attr.CopyIn(t, ruleAttrAddr); err != nil {
		return 0, nil, linuxerr.EFAULT
	}

	if attr.AllowedAccess == 0 {
		return 0, nil, linuxerr.ENOMSG
	}
	if (attr.AllowedAccess &^ ruleset.HandledAccessFS()) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	parentFile := t.GetFile(attr.ParentFD)
	if parentFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer parentFile.DecRef(t)

	if _, isRuleset := parentFile.Impl().(*vfs.LandlockRulesetFileDescription); isRuleset {
		return 0, nil, linuxerr.EBADFD
	}

	vd := parentFile.VirtualDentry()
	// A file that lives on a mount the application can never reach through the
	// mount tree cannot be named by a rule, so it is rejected outright rather
	// than silently added as a rule nothing will ever match. This covers anonfs,
	// pipefs, sockfs, nsfs, the internal tmpfs behind memfd_create(2) and SysV
	// shm, and the host mount holding donated host FDs, matching the set of
	// filesystems Linux marks MNT_INTERNAL.
	//
	// Matches Linux [security/landlock/syscalls.c]:get_path_from_fd() checking MNT_INTERNAL / SB_NOUSER
	if mnt := vd.Mount(); mnt == nil || mnt.Internal() {
		return 0, nil, linuxerr.EBADFD
	}

	stat, err := parentFile.Stat(t, vfs.StatOptions{})
	if err != nil {
		return 0, nil, err
	}

	isDir := linux.FileMode(stat.Mode).IsDir()
	if !isDir && (attr.AllowedAccess&^landlockAccessFile) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// The rule is keyed by the file itself, as Linux keys it by struct inode, so
	// that it follows the file rather than the name it was added under. Linux
	// also takes a reference to that inode, which keeps it alive for as long as
	// the rule names it; PinInodeIdentity() is how a filesystem that has no
	// inode to hold is told to keep the identity meaningful instead.
	vd.Dentry().PinInodeIdentity()
	id := vd.Dentry().InodeIdentity()
	if !id.Ok() {
		// The file's filesystem cannot name it, which the checks above should
		// already have excluded. Reject it as get_path_from_fd() rejects a file
		// that has no place in the mount tree.
		return 0, nil, linuxerr.EBADFD
	}

	ruleset.InsertRule(id, attr.AllowedAccess)
	return 0, nil, nil
}

// LandlockRestrictSelf implements Linux syscall landlock_restrict_self(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_restrict_self()
func LandlockRestrictSelf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFD := args[0].Int()
	flags := args[1].Uint()

	// The no_new_privs check comes before anything the caller passed in. Linux
	// moved it there in commit eba39ca4b155 ("landlock: Change
	// landlock_restrict_self(2) check ordering") so that a thread which is not
	// allowed to sandbox itself learns that first, whatever else is wrong with
	// its call.
	if !t.GetNoNewPrivs() && !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.UserNamespace()) {
		return 0, nil, linuxerr.EPERM
	}

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	rulesetFile := t.GetFile(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)
	// get_ruleset_from_fd() takes the fd with fdget(), which treats an O_PATH
	// descriptor as though it were closed, so the answer is EBADF, not the
	// EBADFD of a descriptor that is open but not a ruleset.
	if rulesetFile.StatusFlags()&linux.O_PATH != 0 {
		return 0, nil, linuxerr.EBADF
	}

	ruleset, err := vfs.LandlockRulesetFromFD(rulesetFile, linux.O_RDONLY)
	if err != nil {
		return 0, nil, err
	}

	currentDomain := t.LandlockDomain()
	newDomain, err := currentDomain.Merge(ruleset)
	if err != nil {
		return 0, nil, err
	}

	t.SetLandlockDomain(newDomain)
	return 0, nil, nil
}
