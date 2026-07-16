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
	"gvisor.dev/gvisor/pkg/sentry/unique_name_landlock"
)

// LandlockCreateRuleset implements landlock_create_ruleset(2).
func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	attrAddr := args[0].Pointer()
	size := args[1].SizeT()
	flags := args[2].Uint()

	if flags != 0 {
		if attrAddr != 0 || size != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_VERSION {
			return 1, nil, nil // ABI v1
		}
		return 0, nil, linuxerr.EINVAL
	}

	if attrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}

	if size < 8 {
		return 0, nil, linuxerr.EINVAL
	}

	var attr linux.LandlockRulesetAttr
	// Copy only what we support (8 bytes).
	if _, err := t.CopyInBytes(attrAddr, attr.MarshalBytes(nil)[:8]); err != nil {
		return 0, nil, err
	}

	if (attr.HandledAccessFS & linux.LANDLOCK_MASK_ACCESS_FS) != attr.HandledAccessFS {
		return 0, nil, linuxerr.EINVAL
	}

	// Check if user passed extra non-zero bytes.
	if size > 8 {
		if err := checkExtraBytesZero(t, attrAddr+8, int(size-8)); err != nil {
			return 0, nil, err
		}
	}

	fd, err := unique_name_landlock.NewRuleset(t, t.Kernel().VFS(), attr.HandledAccessFS)
	if err != nil {
		return 0, nil, err
	}

	fdNo, err := t.NewFDFromVFS(0, fd, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		fd.DecRef(t)
		return 0, nil, err
	}

	return uintptr(fdNo), nil, nil
}

func checkExtraBytesZero(t *kernel.Task, addr hostarch.Addr, size int) error {
	if size <= 0 {
		return nil
	}
	// Cap buffer size to avoid large allocations.
	// User size is checked in caller, but just in case.
	if size > 4096 {
		size = 4096
	}
	buf := make([]byte, size)
	if _, err := t.CopyInBytes(addr, buf); err != nil {
		return err
	}
	for _, b := range buf {
		if b != 0 {
			return linuxerr.E2BIG
		}
	}
	return nil
}

// LandlockAddRule implements landlock_add_rule(2).
func LandlockAddRule(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFd := args[0].Int()
	ruleType := args[1].Int()
	ruleAttrAddr := args[2].Pointer()
	flags := args[3].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	if ruleType != linux.LANDLOCK_RULE_PATH_BENEATH {
		return 0, nil, linuxerr.EINVAL
	}

	if ruleAttrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}

	var buf [12]byte
	if _, err := t.CopyInBytes(ruleAttrAddr, buf[:]); err != nil {
		return 0, nil, err
	}
	allowedAccess := hostarch.ByteOrder.Uint64(buf[0:8])
	parentFd := int32(hostarch.ByteOrder.Uint32(buf[8:12]))

	file := t.GetFile(rulesetFd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	ruleset, ok := file.Impl().(*unique_name_landlock.Ruleset)
	if !ok {
		return 0, nil, linuxerr.EBADFD
	}

	if !file.Writable() {
		return 0, nil, linuxerr.EPERM
	}

	parentFile := t.GetFile(parentFd)
	if parentFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer parentFile.DecRef(t)

	if _, ok := parentFile.Impl().(*unique_name_landlock.Ruleset); ok {
		return 0, nil, linuxerr.EBADFD
	}

	vd := parentFile.VirtualDentry()
	if !vd.Ok() {
		return 0, nil, linuxerr.EBADFD
	}

	fsType := vd.Mount().Filesystem().FilesystemType().Name()
	if fsType == "sockfs" || fsType == "pipefs" || fsType == "nsfs" {
		return 0, nil, linuxerr.EBADFD
	}

	if err := ruleset.AddRule(t, vd, allowedAccess); err != nil {
		return 0, nil, err
	}

	return 0, nil, nil
}

// LandlockRestrictSelf implements landlock_restrict_self(2).
func LandlockRestrictSelf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFd := args[0].Int()
	flags := args[1].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	if !t.NoNewPrivileges() && !t.Credentials().HasSelfCapability(linux.CAP_SYS_ADMIN) {
		return 0, nil, linuxerr.EPERM
	}

	file := t.GetFile(rulesetFd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	ruleset, ok := file.Impl().(*unique_name_landlock.Ruleset)
	if !ok {
		return 0, nil, linuxerr.EBADFD
	}

	if !file.Readable() {
		return 0, nil, linuxerr.EPERM
	}

	if err := t.RestrictLandlock(ruleset); err != nil {
		return 0, nil, err
	}

	return 0, nil, nil
}
