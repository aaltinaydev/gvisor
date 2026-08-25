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

func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	attrAddr := args[0].Pointer()
	size := args[1].SizeT()
	flags := args[2].Uint()

	if flags != 0 {
		if attrAddr != 0 || size != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_VERSION {
			return uintptr(linux.LandlockAbiVersion), nil, nil
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_ERRATA {
			return uintptr(linux.LandlockErrata), nil, nil
		}
		return 0, nil, linuxerr.EINVAL
	}

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

func LandlockAddRule(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
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

	ruleset, err := vfs.LandlockRulesetFromFD(rulesetFile, linux.O_WRONLY)
	if err != nil {
		return 0, nil, err
	}

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
	if mnt := vd.Mount(); mnt == nil || mnt.Internal() {
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

	vd.Dentry().PinInodeIdentity()
	id := vd.Dentry().InodeIdentity()
	if !id.Ok() {
		return 0, nil, linuxerr.EBADFD
	}

	ruleset.InsertRule(id, attr.AllowedAccess)
	return 0, nil, nil
}

func LandlockRestrictSelf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFD := args[0].Int()
	flags := args[1].Uint()

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
