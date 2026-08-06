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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
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
			return uintptr(linux.LandlockAbiVersion), nil, nil
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_ERRATA {
			return 0, nil, nil
		}
		return 0, nil, linuxerr.EINVAL
	}

	t.Kernel().EmitUnimplementedEvent(t, sysno)
	return 0, nil, linuxerr.ENOSYS
}
