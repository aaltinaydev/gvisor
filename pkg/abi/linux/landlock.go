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

// Landlock UAPI definitions and constants.
// Matches Linux [include/uapi/linux/landlock.h]

// Landlock create_ruleset flags.
// Matches Linux [include/uapi/linux/landlock.h]:landlock_create_ruleset_flags
const (
	LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
)

// Landlock rule types.
// Matches Linux [include/uapi/linux/landlock.h]:landlock_rule_type
const (
	LANDLOCK_RULE_PATH_BENEATH = 1
	LANDLOCK_RULE_NET_PORT     = 2
)

// Landlock filesystem access rights (ABI v1-v5).
// Matches Linux [include/uapi/linux/landlock.h]:fs_access
const (
	LANDLOCK_ACCESS_FS_EXECUTE     = 1 << 0
	LANDLOCK_ACCESS_FS_WRITE_FILE  = 1 << 1
	LANDLOCK_ACCESS_FS_READ_FILE   = 1 << 2
	LANDLOCK_ACCESS_FS_READ_DIR    = 1 << 3
	LANDLOCK_ACCESS_FS_REMOVE_DIR  = 1 << 4
	LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
	LANDLOCK_ACCESS_FS_MAKE_CHAR   = 1 << 6
	LANDLOCK_ACCESS_FS_MAKE_DIR    = 1 << 7
	LANDLOCK_ACCESS_FS_MAKE_REG    = 1 << 8
	LANDLOCK_ACCESS_FS_MAKE_SOCK   = 1 << 9
	LANDLOCK_ACCESS_FS_MAKE_FIFO   = 1 << 10
	LANDLOCK_ACCESS_FS_MAKE_BLOCK  = 1 << 11
	LANDLOCK_ACCESS_FS_MAKE_SYM    = 1 << 12
	LANDLOCK_ACCESS_FS_REFER       = 1 << 13
	LANDLOCK_ACCESS_FS_TRUNCATE    = 1 << 14
	LANDLOCK_ACCESS_FS_IOCTL_DEV   = 1 << 15
)

// Landlock limits and access masks.
// Matches Linux [security/landlock/limits.h]
const (
	LANDLOCK_MAX_NUM_LAYERS = 16

	LANDLOCK_ACCESS_FS_V1 = LANDLOCK_ACCESS_FS_EXECUTE |
		LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR |
		LANDLOCK_ACCESS_FS_REMOVE_DIR |
		LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_MAKE_CHAR |
		LANDLOCK_ACCESS_FS_MAKE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_REG |
		LANDLOCK_ACCESS_FS_MAKE_SOCK |
		LANDLOCK_ACCESS_FS_MAKE_FIFO |
		LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		LANDLOCK_ACCESS_FS_MAKE_SYM

	LANDLOCK_ACCESS_FS_FILE_MASK = LANDLOCK_ACCESS_FS_EXECUTE |
		LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_TRUNCATE |
		LANDLOCK_ACCESS_FS_IOCTL_DEV
)

// LandlockRulesetAttr is the argument of sys_landlock_create_ruleset().
// Matches Linux [include/uapi/linux/landlock.h]:struct landlock_ruleset_attr
type LandlockRulesetAttr struct {
	HandledAccessFS  uint64
	HandledAccessNet uint64
	Scoped           uint64
}

// LandlockPathBeneathAttr is the argument of sys_landlock_add_rule() for LANDLOCK_RULE_PATH_BENEATH.
// Matches Linux [include/uapi/linux/landlock.h]:struct landlock_path_beneath_attr
type LandlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
}

// LandlockNetPortAttr is the argument of sys_landlock_add_rule() for LANDLOCK_RULE_NET_PORT.
// Matches Linux [include/uapi/linux/landlock.h]:struct landlock_net_port_attr
type LandlockNetPortAttr struct {
	AllowedAccess uint64
	Port          uint64
}
