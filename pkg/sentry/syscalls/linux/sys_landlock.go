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
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// LandlockCreateRuleset implements Linux syscall landlock_create_ruleset(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_create_ruleset()
func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	attrAddr := args[0].Pointer()
	size := args[1].SizeT()
	flags := args[2].Uint()

	if flags != 0 {
		if flags == linux.LANDLOCK_CREATE_RULESET_VERSION {
			if attrAddr != 0 || size != 0 {
				return 0, nil, linuxerr.EINVAL
			}
			return uintptr(linux.LANDLOCK_CREATE_RULESET_VERSION), nil, nil
		}
		return 0, nil, linuxerr.EINVAL
	}

	if attrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}
	if size < 8 {
		return 0, nil, linuxerr.EINVAL
	}
	if size > hostarch.PageSize {
		return 0, nil, linuxerr.E2BIG
	}

	// Matches Linux [security/landlock/syscalls.c]:copy_min_struct_from_user()
	var attr linux.LandlockRulesetAttr
	copySize := size
	if copySize > 24 {
		copySize = 24
	}

	buf := make([]byte, copySize)
	if _, err := t.CopyInBytes(attrAddr, buf); err != nil {
		return 0, nil, linuxerr.EFAULT
	}

	if copySize >= 8 {
		attr.HandledAccessFS = hostarch.ByteOrder.Uint64(buf[0:8])
	}
	if copySize >= 16 {
		attr.HandledAccessNet = hostarch.ByteOrder.Uint64(buf[8:16])
	}
	if copySize >= 24 {
		attr.Scoped = hostarch.ByteOrder.Uint64(buf[16:24])
	}

	if size > 24 {
		extraBuf := make([]byte, size-24)
		if _, err := t.CopyInBytes(attrAddr+24, extraBuf); err != nil {
			return 0, nil, linuxerr.EFAULT
		}
		for _, b := range extraBuf {
			if b != 0 {
				return 0, nil, linuxerr.E2BIG
			}
		}
	}

	if (attr.HandledAccessFS &^ linux.LANDLOCK_ACCESS_FS_V1) != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if attr.HandledAccessFS == 0 {
		return 0, nil, linuxerr.ENOMSG
	}
	if size >= 16 && attr.HandledAccessNet != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if size >= 24 && attr.Scoped != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	ruleset := vfs.NewLandlockRuleset(attr.HandledAccessFS)
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
	if ruleType != linux.LANDLOCK_RULE_PATH_BENEATH {
		return 0, nil, linuxerr.EINVAL
	}

	rulesetFile := t.GetFile(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)

	ruleset, err := vfs.LandlockRulesetFromFD(rulesetFile, linux.O_WRONLY)
	if err != nil {
		return 0, nil, err
	}

	if ruleAttrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}

	var attr linux.LandlockPathBeneathAttr
	buf := make([]byte, 12)
	if _, err := t.CopyInBytes(ruleAttrAddr, buf); err != nil {
		return 0, nil, linuxerr.EFAULT
	}
	attr.AllowedAccess = hostarch.ByteOrder.Uint64(buf[0:8])
	attr.ParentFD = int32(hostarch.ByteOrder.Uint32(buf[8:12]))

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
	// Matches Linux [security/landlock/syscalls.c]:get_path_from_fd() checking MNT_INTERNAL / SB_NOUSER
	if t.Kernel().VFS().IsAnonVD(vd) || vd.Mount() == t.Kernel().PipeMount() || vd.Mount() == t.Kernel().SocketMount() {
		return 0, nil, linuxerr.EBADFD
	}

	stat, err := parentFile.Stat(t, vfs.StatOptions{})
	if err != nil {
		return 0, nil, err
	}

	isDir := linux.FileMode(stat.Mode).IsDir()
	if !isDir && (attr.AllowedAccess&^linux.LANDLOCK_ACCESS_FS_FILE_MASK) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	vfsroot := vfs.VirtualDentry{}
	parentPath, err := t.Kernel().VFS().PathnameWithDeleted(t, vfsroot, vd)
	if err != nil {
		return 0, nil, err
	}

	ruleset.AddPathRule(parentPath, attr.AllowedAccess)
	return 0, nil, nil
}

// LandlockRestrictSelf implements Linux syscall landlock_restrict_self(2).
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_restrict_self()
func LandlockRestrictSelf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFD := args[0].Int()
	flags := args[1].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	if !t.GetNoNewPrivs() && !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, t.UserNamespace()) {
		return 0, nil, linuxerr.EPERM
	}

	rulesetFile := t.GetFile(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)

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
