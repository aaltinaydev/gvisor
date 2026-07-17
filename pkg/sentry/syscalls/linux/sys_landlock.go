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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/landlock"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// rulesetFD implements vfs.FileDescriptionImpl for Landlock ruleset.
type rulesetFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	ruleset *landlock.Ruleset
}

var _ vfs.FileDescriptionImpl = (*rulesetFD)(nil)

// Release implements vfs.FileDescriptionImpl.Release.
func (r *rulesetFD) Release(ctx context.Context) {
	r.ruleset.Destroy()
}

// LandlockCreateRuleset implements linux syscall landlock_create_ruleset(2).
// Matches Linux security/landlock/syscalls.c:sys_landlock_create_ruleset
func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	attrAddr := args[0].Pointer()
	size := args[1].SizeT()
	flags := args[2].Uint()

	if flags != 0 {
		if attrAddr != 0 || size != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_VERSION {
			return 1, nil, nil // Return version 1.
		}
		return 0, nil, linuxerr.EINVAL
	}

	attrSizeBytes := (&linux.LandlockRulesetAttr{}).SizeBytes()

	if attrAddr == 0 {
		return 0, nil, linuxerr.EFAULT
	}
	if size > hostarch.PageSize {
		return 0, nil, linuxerr.E2BIG
	}
	sizeBytes := int(size)
	if sizeBytes < 8 { // Must be at least sizeof(handled_access_fs)
		return 0, nil, linuxerr.EINVAL
	}

	copySize := sizeBytes
	if copySize > attrSizeBytes {
		copySize = attrSizeBytes
	}

	buf := make([]byte, attrSizeBytes)
	if _, err := t.CopyInBytes(attrAddr, buf[:copySize]); err != nil {
		return 0, nil, err
	}

	if sizeBytes > attrSizeBytes {
		remSize := sizeBytes - attrSizeBytes
		remBuf := make([]byte, remSize)
		if _, err := t.CopyInBytes(attrAddr+hostarch.Addr(attrSizeBytes), remBuf); err != nil {
			return 0, nil, err
		}
		for _, b := range remBuf {
			if b != 0 {
				return 0, nil, linuxerr.E2BIG
			}
		}
	}

	var attr linux.LandlockRulesetAttr
	attr.UnmarshalBytes(buf)

	// We only support FS (and only V1), Net and Scoped must be 0.
	if attr.HandledAccessNet != 0 || attr.Scoped != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// For version 1, we only support FS accesses up to bit 12.
	// Reject anything higher.
	if (attr.HandledAccessFS & ^uint64(linux.LANDLOCK_MASK_ACCESS_FS_V1)) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	r := landlock.NewRuleset(attr.HandledAccessFS)
	vfsObj := t.Kernel().VFS()
	vd := vfsObj.NewAnonVirtualDentry("[landlock-ruleset]")
	defer vd.DecRef(t)

	fdDesc := &rulesetFD{
		ruleset: r,
	}
	if err := fdDesc.vfsfd.Init(fdDesc, linux.O_RDWR, auth.CredentialsFromContext(t), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return 0, nil, err
	}
	defer fdDesc.vfsfd.DecRef(t)

	fd, err := t.NewFDFrom(0, &fdDesc.vfsfd, kernel.FDFlags{
		CloseOnExec: true,
	})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(fd), nil, nil
}

// LandlockAddRule implements linux syscall landlock_add_rule(2).
// Matches Linux security/landlock/syscalls.c:sys_landlock_add_rule
func LandlockAddRule(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFDVal := args[0].Int()
	ruleType := args[1].Int()
	ruleAttrAddr := args[2].Pointer()
	flags := args[3].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	if ruleType != linux.LANDLOCK_RULE_PATH_BENEATH {
		return 0, nil, linuxerr.EINVAL
	}

	rulesetFile := t.GetFile(rulesetFDVal)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)

	// Matches Linux security/landlock/syscalls.c:get_ruleset_from_fd() (via fdget)
	if rulesetFile.StatusFlags()&linux.O_PATH != 0 {
		return 0, nil, linuxerr.EBADF
	}

	rFD, ok := rulesetFile.Impl().(*rulesetFD)
	if !ok {
		return 0, nil, linuxerr.EBADFD
	}

	var ruleAttr linux.LandlockPathBeneathAttr
	if _, err := ruleAttr.CopyIn(t, ruleAttrAddr); err != nil {
		return 0, nil, err
	}

	allowedAccess := uint64(ruleAttr.AllowedAccess[0]) | (uint64(ruleAttr.AllowedAccess[1]) << 32)
	if allowedAccess == 0 {
		return 0, nil, linuxerr.ENOMSG
	}

	handled := rFD.ruleset.HandledAccessFS
	if (allowedAccess & ^handled) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	targetFile := t.GetFile(ruleAttr.ParentFD)
	if targetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer targetFile.DecRef(t)

	// Validate that targetFile is not a ruleset FD.
	if _, ok := targetFile.Impl().(*rulesetFD); ok {
		return 0, nil, linuxerr.EBADFD
	}

	if targetFile.Mount().NeverConnected() {
		return 0, nil, linuxerr.EBADFD
	}

	stat, err := targetFile.Stat(t, vfs.StatOptions{Mask: linux.STATX_TYPE})
	if err != nil {
		return 0, nil, err
	}
	isDir := (stat.Mode & linux.S_IFMT) == linux.S_IFDIR

	if !isDir {
		// Files only get access rights that make sense.
		if (allowedAccess & ^uint64(linux.LANDLOCK_ACCESS_FS_FILE)) != 0 {
			return 0, nil, linuxerr.EINVAL
		}
	}

	if err := rFD.ruleset.AddRule(targetFile.Dentry(), allowedAccess); err != nil {
		return 0, nil, err
	}

	return 0, nil, nil
}

// LandlockRestrictSelf implements linux syscall landlock_restrict_self(2).
// Matches Linux security/landlock/syscalls.c:sys_landlock_restrict_self
func LandlockRestrictSelf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFDVal := args[0].Int()
	flags := args[1].Uint()

	// Check credentials before flags.
	if !t.GetNoNewPrivs() && !t.Credentials().HasSelfCapability(linux.CAP_SYS_ADMIN) {
		return 0, nil, linuxerr.EPERM
	}

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	rulesetFile := t.GetFile(rulesetFDVal)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)

	// Matches Linux security/landlock/syscalls.c:get_ruleset_from_fd() (via fdget)
	if rulesetFile.StatusFlags()&linux.O_PATH != 0 {
		return 0, nil, linuxerr.EBADF
	}

	rFD, ok := rulesetFile.Impl().(*rulesetFD)
	if !ok {
		return 0, nil, linuxerr.EBADFD
	}

	var currentDom *landlock.Domain
	if t.Credentials().LandlockDomain != nil {
		currentDom = t.Credentials().LandlockDomain.(*landlock.Domain)
		if len(currentDom.HandledAccessFS) >= linux.LANDLOCK_MAX_NUM_LAYERS {
			return 0, nil, linuxerr.E2BIG
		}
	}

	newDom := currentDom.Merge(rFD.ruleset)
	t.SetLandlockDomain(newDom)

	return 0, nil, nil
}
