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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/landlock"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// LandlockCreateRuleset implements sys_landlock_create_ruleset(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_create_ruleset()
func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	attrAddr := args[0].Pointer()
	size := uint64(args[1].SizeT())
	flags := uint32(args[2].Uint64())

	if flags != 0 {
		if attrAddr != 0 || size != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_VERSION {
			return 1, nil, nil
		}
		return 0, nil, linuxerr.EINVAL
	}

	if size < 8 {
		return 0, nil, linuxerr.EINVAL
	}
	if attrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}

	var attr linux.LandlockRulesetAttr
	if _, err := attr.CopyIn(t, attrAddr); err != nil {
		return 0, nil, err
	}

	// Matches Linux [include/linux/uaccess.h]:copy_struct_from_user()
	attrSize := uint64(attr.SizeBytes())
	if size > attrSize {
		if size > hostarch.PageSize {
			return 0, nil, linuxerr.E2BIG
		}
		buf := make([]byte, size-attrSize)
		if _, err := t.CopyInBytes(attrAddr+hostarch.Addr(attrSize), buf); err != nil {
			return 0, nil, err
		}
		for _, b := range buf {
			if b != 0 {
				return 0, nil, linuxerr.E2BIG
			}
		}
	}

	if attr.HandledAccessFS == 0 {
		return 0, nil, linuxerr.ENOMSG
	}
	if (attr.HandledAccessFS &^ linux.LANDLOCK_MASK_ACCESS_FS) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	ruleset := landlock.NewRuleset(attr.HandledAccessFS)
	fdImpl, err := landlock.NewRulesetFD(t, t.Kernel().VFS(), t.Credentials(), ruleset)
	if err != nil {
		return 0, nil, err
	}
	defer fdImpl.DecRef(t)

	fd, err := t.NewFDFrom(0, fdImpl, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

// LandlockAddRule implements sys_landlock_add_rule(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_add_rule()
func LandlockAddRule(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFD := args[0].Int()
	ruleType := args[1].Uint64()
	ruleAttrAddr := args[2].Pointer()
	flags := uint32(args[3].Uint64())

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if ruleType != linux.LANDLOCK_RULE_PATH_BENEATH {
		return 0, nil, linuxerr.EINVAL
	}

	rulesetFile, _ := t.FDTable().Get(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)

	rfd, ok := rulesetFile.Impl().(*landlock.RulesetFD)
	if !ok {
		return 0, nil, linuxerr.EBADFD
	}
	if !rulesetFile.IsWritable() {
		// Matches Linux [security/landlock/syscalls.c]:get_ruleset_from_fd()
		return 0, nil, linuxerr.EPERM
	}
	if rfd.Ruleset.NumLayers != 1 {
		return 0, nil, linuxerr.EBADFD
	}

	if ruleAttrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}

	var ruleAttr linux.LandlockPathBeneathAttr
	if _, err := ruleAttr.CopyIn(t, ruleAttrAddr); err != nil {
		return 0, nil, err
	}

	if ruleAttr.AllowedAccess == 0 {
		return 0, nil, linuxerr.ENOMSG
	}
	if (ruleAttr.AllowedAccess &^ rfd.Ruleset.HandledAccessFS) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	parentFile, _ := t.FDTable().Get(ruleAttr.ParentFD)
	if parentFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer parentFile.DecRef(t)

	// Disallow ruleset FDs and pseudo filesystems
	// Matches Linux [security/landlock/syscalls.c]:get_path_from_fd()
	if _, isRuleset := parentFile.Impl().(*landlock.RulesetFD); isRuleset {
		return 0, nil, linuxerr.EBADFD
	}

	vd := parentFile.VirtualDentry()
	if !vd.Ok() || vd.Dentry() == nil {
		return 0, nil, linuxerr.EBADFD
	}

	if fs := vd.Mount().Filesystem(); fs != nil {
		name := fs.FilesystemType().Name()
		if name == "pipefs" || name == "socketfs" || name == "anon_inodefs" {
			return 0, nil, linuxerr.EBADFD
		}
	}

	stat, err := parentFile.Stat(t, vfs.StatOptions{Mask: linux.STATX_TYPE})
	if err != nil {
		return 0, nil, err
	}

	fileType := linux.FileMode(stat.Mode).FileType()
	if fileType == linux.ModeNamedPipe || fileType == linux.ModeSocket {
		return 0, nil, linuxerr.EBADFD
	}

	// Non-directory files only get access rights that apply to files.
	// Matches Linux [security/landlock/fs.c]:landlock_append_fs_rule()
	if !linux.FileMode(stat.Mode).IsDir() && (ruleAttr.AllowedAccess&^linux.LANDLOCK_MASK_ACCESS_FS_FILE) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	rfd.Ruleset.AddPathBeneathRule(vd.Dentry(), ruleAttr.AllowedAccess)
	return 0, nil, nil
}

// LandlockRestrictSelf implements sys_landlock_restrict_self(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_restrict_self()
func LandlockRestrictSelf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFD := args[0].Int()
	flags := uint32(args[1].Uint64())

	// Escalation Check: requires no_new_privs or CAP_SYS_ADMIN in current user namespace.
	// Matches Linux [security/landlock/syscalls.c]:sys_landlock_restrict_self()
	if !t.GetNoNewPrivs() && !t.Credentials().HasSelfCapability(linux.CAP_SYS_ADMIN) {
		return 0, nil, linuxerr.EPERM
	}

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	rulesetFile, _ := t.FDTable().Get(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)

	rfd, ok := rulesetFile.Impl().(*landlock.RulesetFD)
	if !ok {
		return 0, nil, linuxerr.EBADFD
	}

	if !rulesetFile.IsReadable() {
		// Matches Linux [security/landlock/syscalls.c]:get_ruleset_from_fd()
		return 0, nil, linuxerr.EPERM
	}

	var curDom *landlock.LandlockDomain
	if dom, ok := t.Credentials().LandlockDomain.(*landlock.LandlockDomain); ok {
		curDom = dom
	}

	// Matches Linux [security/landlock/ruleset.c]:landlock_merge_ruleset()
	newDom, err := curDom.Merge(rfd.Ruleset)
	if err != nil {
		return 0, nil, err
	}

	t.SetLandlockDomain(newDom)
	return 0, nil, nil
}
