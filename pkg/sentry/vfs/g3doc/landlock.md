# Landlock

Landlock is a Linux security module that lets an unprivileged thread restrict
its own access to the filesystem, and pass that restriction on to everything it
spawns. See landlock(7). The sentry implements ABI version 1: the three
syscalls `landlock_create_ruleset(2)`, `landlock_add_rule(2)` and
`landlock_restrict_self(2)`, and the thirteen `LANDLOCK_ACCESS_FS_*` rights that
version 1 defines.

This document describes how that implementation works. The bulk of it lives in
`pkg/sentry/vfs/landlock.go`; the enforcement points live in each
`vfs.FilesystemImpl`.

## Overview

A thread sandboxes itself in three steps:

1.  `landlock_create_ruleset(2)` creates an empty **ruleset** and returns a file
    descriptor for it. The ruleset declares the set of rights it *handles* —
    the rights it will deny unless a rule grants them. Rights it does not handle
    are left entirely alone.

2.  `landlock_add_rule(2)` adds a **rule** to the ruleset: a file or directory,
    named by a file descriptor, plus the subset of the handled rights that are
    allowed on it and everything beneath it.

3.  `landlock_restrict_self(2)` turns the ruleset into a new **layer** of the
    calling thread's **domain**. The domain is what is actually enforced. It is
    inherited by children and survives `execve(2)`.

Calling `landlock_restrict_self(2)` again stacks another layer. Layers only ever
intersect: an operation is allowed if *every* layer allows it, so a thread can
never widen its own access, only narrow it. There is a limit of
`LANDLOCK_MAX_NUM_LAYERS` (16) layers.

An access is checked by walking the target file and its ancestors upward. Within
one layer, a right is granted if the file or any ancestor has a rule granting
it; rights accumulate as the walk proceeds. A layer allows the operation once
every right that the layer both handles and the operation requires has been
granted. Denied operations fail with `EACCES`, except where noted below.

## Objects

```
Credentials ──► LandlockDomain ──► []LandlockDomainLayer
                (immutable)         { handledAccessFS, rules }
                                                        │
LandlockRuleset ──► LandlockRulesetFileDescription      │
(mutable, pre-enforcement)                              ▼
                                    map[InodeIdentity]uint64
```

### `LandlockRuleset`

A mutable set of rules plus the handled-access mask, held behind a mutex. It is
the object `landlock_add_rule(2)` writes to. `NewLandlockRuleset()` matches
Linux's `landlock_create_ruleset()`, and `InsertRule()` matches
`landlock_insert_rule()` — adding a rule for a file that already has one unions
the two rights masks rather than replacing.

### `LandlockRulesetFileDescription`

The anonymous file description a ruleset FD refers to, corresponding to Linux's
`ruleset_fops`. It is created on the anonymous mount and is `CloseOnExec`.
`Release()` does nothing: rules are plain values holding no references, and
closing the last descriptor cannot disturb a domain built from the ruleset,
since `Merge()` copies the rules it takes. Go's garbage collector reclaims the
ruleset once nothing refers to it.

`LandlockRulesetFromFD()` recovers the ruleset from a `*vfs.FileDescription`,
enforcing the same access-mode requirement Linux's `get_ruleset_from_fd()` does
(`landlock_add_rule(2)` needs write access; `landlock_restrict_self(2)` needs
read).

### `LandlockDomain` and `LandlockDomainLayer`

A domain is an immutable slice of layers. Each layer is a snapshot of one
ruleset taken at the moment `landlock_restrict_self(2)` was called: its handled
mask plus a copy of its rules map. Later mutations to the ruleset FD do not
affect a domain already derived from it.

`Merge()` matches `landlock_merge_ruleset()`. It never mutates the receiver — it
returns a brand new domain with one more layer, or `E2BIG` past the layer limit.
Immutability is what lets a domain be shared freely between forked credentials
without any locking.

Each domain also keeps a pointer to the domain it was derived from. That chain
is Linux's `struct landlock_hierarchy`, and it exists for `ptrace(2)` scoping;
see below.

## `ptrace(2)` scoping

Landlock restricts `ptrace(2)` from ABI v1 onward, independently of any
filesystem right: `hook_ptrace_access_check()` and `hook_ptrace_traceme()` are
registered unconditionally. Without this, the filesystem policy would be
trivially escapable — a sandboxed thread could attach to an unsandboxed one and
have it open whatever it liked.

`LandlockDomain.ScopeLE()` matches `domain_scope_le()`: it walks the target's
parent chain looking for the tracer's own domain. A tracer may act on a target
only if the target is confined by the tracer's domain or a descendant of it. An
unsandboxed tracer may trace anyone; a sandboxed tracer may never trace an
unsandboxed target.

`kernel.Task.canTraceLandlock()` applies this from both `CanTrace()` and
`canTraceLocked()`, which is also how `PTRACE_TRACEME` inherits it — that path
already asks whether the prospective parent could trace the child. It sits after
the same-thread-group short circuit, matching `__ptrace_may_access()`, which
returns early for `same_thread_group()` before consulting any LSM.

The check applies to `PTRACE_MODE_READ` as well as `PTRACE_MODE_ATTACH`, so
`/proc/[pid]/mem` and the other `CanTrace`-gated procfs files are covered too.

## Where the domain lives

The domain hangs off `auth.Credentials`, not off `kernel.Task`:

```go
type Credentials struct {
    ...
    LandlockDomain LandlockDomain // an interface; the concrete type is *vfs.LandlockDomain
}
```

`auth.LandlockDomain` is a marker interface with a single no-op method. It
exists only so that `auth` — which cannot import `vfs` — can carry the domain
without typing the field as `any`.

Putting the domain in the credentials mirrors Linux, which reaches it through
the LSM blob on `cred->security`, and it buys two properties for free:

*   **Inheritance.** `clone(2)` and `execve(2)` carry the credentials along, so
    the domain comes with them. No separate plumbing is needed.

*   **Credential substitution.** When a filesystem operates on its own backing
    files under substituted credentials, the sandboxed task's domain is not
    along for the ride. This matters for overlayfs: copy-up touches upper-layer
    files that no rule could ever name, and it runs under filesystem credentials
    exactly as Linux runs it under `ovl_override_creds()`.

`Task.LandlockDomain()` and `Task.SetLandlockDomain()` wrap this. Because
`Task.creds` is an atomic pointer, testing for a domain on the VFS fast path
does not take `t.mu`; `SetLandlockDomain()` forks the (immutable) credentials
and stores the new pointer, and so must run on the task goroutine.

`LandlockDomainFromCredentials()` does the type assertion and returns `nil` for
unrestricted credentials. Every `*LandlockDomain` method is nil-safe and treats
`nil` as "no restriction".

## Identifying files: `InodeIdentity`

Rules are keyed by **file**, not by pathname, exactly as Linux keys them by
`struct inode`. Keying by pathname would be wrong in three ways: a hard link or
a bind mount reaching the same file by another name would bypass the rule; a
rename of a covered directory would silently drop the rule; and the name a rule
was added under is not the name an operation is checked against.

`vfs.InodeIdentity` is the comparable value that names a file:

```go
type InodeIdentity struct {
    ok       bool
    fsID     uint64
    devMajor uint32
    devMinor uint32
    ino      uint64
}
```

`fsID` is a per-`vfs.Filesystem` number that, unlike a device number, is never
reused. Device numbers are: `PutAnonBlockDevMinor()` returns a minor to the pool
when its filesystem is destroyed and rewinds the allocator so that the very next
filesystem is handed it back. Without `fsID`, a rule keyed on a file of the
destroyed filesystem would start matching an unrelated file that happened to
share its inode number on the filesystem that inherited the minor — granting
access the domain never allowed. Scoping to the filesystem keeps the existing
granularity (a bind mount shares one `vfs.Filesystem`, so rules still follow the
file across mounts) while making that collision impossible.

It is produced by a new method on every `DentryImpl`:

```go
// InodeIdentity returns a value identifying the file corresponding to the
// Dentry, such that Dentries that are hard links to the same underlying file,
// or that reach it through different mounts, return equal values.
InodeIdentity() InodeIdentity
```

The zero value means "no identity" and is returned by filesystems that cannot
name their files — in practice only anonymous inodes, which no path reaches.
`CheckAccess()` fails closed on a dentry with no identity.

"Keyed by file" is only as sound as the numbers a filesystem mints. Two of
them trust someone else for those numbers. The gofer's come from host inode
keys, which is what the [inode-number reuse](#inode-number-reuse) machinery
below exists to shore up. The FUSE `nodeID` is assigned by the FUSE server —
an ordinary sandboxed process — which may lawfully recycle one after
`FUSE_FORGET` or alias it across files, so a rule on a FUSE file follows
whatever file the server says it does. That stays confined to the one
filesystem (`fsID` scopes it), whose entire contents the server already
controls, so it grants nothing the server could not already fabricate; there
is deliberately no retirement machinery for it.

The `ino` component need not be the number `stat(2)` reports. It only has to be
unique within the filesystem and **stable across destruction and
re-instantiation of the dentries naming the file**, since dentries are cached
and identities outlive them. Per-filesystem choices:

| Filesystem | `ino` source                                                |
| ---------- | ----------------------------------------------------------- |
| tmpfs      | `inode.ino` (counter, never reused)                          |
| kernfs     | `Inode.Ino()` via the `inodeIdentifiable` interface, which `InodeAttrs` satisfies; covers proc, sys, devpts, cgroupfs, mqfs, fuse. host inodes are anonymous and have no identity, and pipefs/sockfs live on internal mounts, so their identities never matter: rules on all three are refused with `EBADFD` |
| fuse       | the server's immutable `nodeID`, not the mutable `i.ino`, so hard links share it |
| gofer      | `inode.ino`, not `inoKey`: unique for synthetic inodes, and shared between hard links because `fs.inoFromKey()` assigns one `ino` per `inoKey` |
| erofs      | `inode.Nid()`                                                |
| overlay    | the identity of the *pre-copy-up layer* file (`lowerVDs[0]`, else `upperVD`) — not the synthesized numbers `Stat` reports, which are rewritten on copy-up and reallocated from `dirInoCache`. See [Copy-up](#copy-up) |
| anonfs     | none (zero value)                                            |

### Copy-up

Reporting the identity of the file on the layer it was found on is not by itself
enough for the overlay, because copy-up gives a non-directory a second home with
an identity of its own. `lookupLocked()` stops at the topmost layer holding a
non-directory, so a dentry instantiated after a copy-up never sees the lower
file, and overlay dentries are destroyed as soon as their last reference goes
away. A rule added on a lower-layer file would stop matching it the first time
the file was written and then looked up afresh — a spurious denial, in the
configuration runsc uses for a container's writable root.

Linux is immune to this: a rule holds a reference to the overlayfs inode, and
copy-up does not replace that inode. gVisor's overlay has no inode of its own to
hold, so `landlock_add_rule(2)` calls an optional method instead:

```go
// PinInodeIdentity asks the FilesystemImpl to keep returning the current
// identity for the file underlying the Dentry for as long as the file exists.
PinInodeIdentity()
```

The overlay implements it by remembering the identity it just handed out. When a
pinned file is copied up, it records the correspondence between the copy's
identity and the pinned one, and `InodeIdentity()` on a dentry that only reaches
the upper layer translates back through it. Only pinned files are tracked, so
this costs memory in proportion to the number of rules rather than to the number
of files ever copied up. Directories need none of it: they are merged, so every
dentry for one keeps its lower layers.

Pins are never released. A ruleset holds no reference the overlay could watch
end, and a domain has no destructor at all, so the two maps grow with the
number of distinct files ever named by a rule and live as long as the overlay
filesystem — where Linux holds an inode reference per rule and drops it when
the ruleset is freed. The entries are small (a map key and value each), the
bound is the number of distinct lower-layer files, and only
`landlock_add_rule(2)` adds one, but a workload that loops creating rulesets
and naming fresh files does grow sentry memory for the mount's lifetime.

### Inode-number reuse

Linux pins the inode a rule refers to with `ihold()`, so a rule can never come
to name a different file. An `InodeIdentity` is only a number, so in principle a
rule can outlive the file it was added for and grant its rights to a later file
that inherits that number.

This is confined to filesystems that take inode numbers from the host — gofer
mounts and overlays stacked on one. tmpfs, kernfs and erofs draw theirs from
per-filesystem counters that are never reused, and an identity carries the
`fsID` of the filesystem it came from, so a number cannot be confused across
filesystems either.

What remains is closed by retiring a file's number when the file is deleted:
once any Landlock ruleset exists (`VirtualFilesystem.LandlockInUse()`), a
deletion the sentry performs — `unlink(2)`, `rmdir(2)`, or a `rename(2)` that
replaces — drops the file's host inode key from `fs.inoByKey` and
`fs.inodeByKey` once its last link is gone
(`[gofer]dentry.releaseInoOnDeletion()`), so a later file the host gives the
same key mints a fresh number that no stale rule can match. To know the last
link went away, the victim is looked up before the unlink when it is not
already cached; the ruleset gate keeps that extra RPC off every workload that
never uses Landlock. The copy-up map above is covered by the same mechanism:
a stale entry keyed on an upper-layer copy's identity is harmless once that
identity can never be minted for another file.

Two residual exposures remain, and both point in the same direction: a stale
rule can only ever **grant**, so what leaks is access to a new file that
reuses a dead file's number — never a denial of something the policy allowed.

The first is a deletion the sentry never observes: a file removed directly on
the host behind an `InteropModeShared` mount keeps its key mapped, so a
host-side replacement inherits its number, and a rule added for the old file
grants access to the new one. The second is a deletion observed through the
wrong mount: two gofer mounts of the same host subtree are two `filesystem`
instances with independent `inoByKey` maps, so a deletion performed through
one retires nothing in the other, and a host-side recreation reusing the key
revives the number — and any stale rule — on the mount the deletion did not
pass through. Retiring across instances would require the sentry to know that
two gofer sessions name the same host tree, which it does not. Both exposures
are inherent to trusting the host for inode numbers, are bounded to files a
rule explicitly named, and are called out in the syscall table's
`PartiallySupported` note; runsc's default configuration mounts disjoint host
subtrees, which leaves only the first.

A remote filesystem that reports no link counts
retires a number on the first unlink instead of the last, which can only
change the `st_ino` a surviving hard link reports after its dentry is evicted
— already not preserved across checkpoint/restore.

Two smaller notes on the same machinery. `LandlockInUse()` is sticky: any
process's first `landlock_create_ruleset(2)` sets it for the life of the
sandbox (it is saved across checkpoint), so from then on every uncached
unlink or rmdir on a gofer mount pays the victim lookup, Landlock user or
not. And after a restore, a rule keyed on a gofer file whose dentry was not
in the saved tree keeps its identity while the file, when next looked up,
mints a fresh number (`inoByKey` is rebuilt from live dentries); the rule
then silently stops matching. That direction is fail-closed — the domain
loses a grant, never gains one — but it is a functional gap for rules on
rarely-touched files across checkpoint/restore.

## Walking the ancestry: `WalkAncestors`

A right granted on a directory applies to everything beneath it, so a check has
to walk from the target file up toward the root, across mount boundaries.

```go
func (vfs *VirtualFilesystem) WalkAncestors(
    ctx context.Context, vd VirtualDentry, toDecRef *[]refs.RefCounter,
    fn func(d *Dentry) bool)
```

`fn` is called on `vd`'s dentry and then each ancestor, and the walk stops when
`fn` returns false, or when it reaches a mount with no mount point to continue
from — the root of the mount namespace, or a mount that was never connected to
one.

The per-filesystem half is a new `FilesystemImpl.WalkAncestors()` that walks
within one filesystem; most implementations delegate to
`genericfstree.WalkAncestors`, which holds `fs.ancestryMu` for the duration.
Filesystems whose dentries have no meaningful path (anonfs, host, pipefs,
sockfs) call `fn` on the dentry alone.

Three subtleties:

*   **Disconnected dentries reach the mount root anyway.** A directory can be
    moved out of the subtree its bind mount exposes, which leaves files under it
    reachable only through descriptors opened before the move. The mount root is
    no longer among their ancestors, so the per-filesystem walk runs to the root
    of the filesystem without passing it. The mount root is visited there
    regardless, before the walk crosses to the mount point: the rights that
    reaching the file through this mount carries are the ones its root has, and
    collecting them keeps a rename from widening access. Linux does the same
    since commit 49c9e09d9610 ("landlock: Fix handling of disconnected
    directories"), which it reports as erratum 3.

*   **Dentries covered by a mount are skipped.** When the walk moves above a
    mount point, the mount point dentry itself is not visited — the mount root
    that covers it was visited in its place. No path names the covered dentry,
    so no rule should be found on it. This mirrors Linux's `follow_up()`.

*   **References are handed back to the caller.** Moving above a mount point
    takes references on the mount point dentry and mount. `WalkAncestors()`
    cannot drop them itself, because the walk runs with filesystem locks held
    and releasing the last reference to a mount point can release the filesystem
    it is on — taking that filesystem's own locks. It appends them to
    `*toDecRef` instead. `ResolvingPath` accumulates them in `rp.toDecRef` and
    `ResolvingPath.Release()` drains them, by which point VFS holds no
    filesystem locks.

Because `fn` runs under filesystem locks, it must not reenter the filesystem.
The dentries it is handed are unreferenced and valid only for the duration of
the call.

## Evaluating a check

`LandlockDomain.CheckAccess()` matches `is_access_to_paths_allowed()`. All
layers are evaluated over a *single* ancestry walk rather than one walk per
layer, using `landlockLayerMasks`:

```go
type landlockLayerMasks struct {
    domain      *LandlockDomain
    remaining   []uint64 // remaining[i]: rights layer i still needs granted
    unsatisfied int      // number of layers with remaining[i] != 0
}
```

*   `newLayerMasks(accessRights)` (Linux: `init_layer_masks()`) seeds
    `remaining[i] = layer[i].handledAccessFS & accessRights`. A layer that
    handles none of the requested rights starts satisfied. If *every* layer
    starts satisfied, `CheckAccess()` returns immediately without walking
    anything — this is the common case for an operation whose rights no layer
    cares about.

*   `unmask(id)` (Linux: `unmask_layers()`) clears, from every layer, the rights
    that that layer's rule for `id` grants, decrementing `unsatisfied` as layers
    become satisfied.

*   The walk stops as soon as `unsatisfied` hits zero.

If any layer is still unsatisfied when the walk ends, the result is `EACCES`. A
`VirtualDentry` that names no file is denied outright: what cannot be checked
against the rules must fail closed.

### Internal mounts are exempt

Files on an internal mount — pipefs, sockfs, nsfs, anonfs, the internal shm
mount that backs `memfd_create(2)`, and the host mount holding donated host FDs
(the application's stdio among them) — are allowed before the walk starts.

No rule can ever name such a file: `landlock_add_rule(2)` takes a path, and no
path leads to these mounts. They are reachable only through `/proc/[pid]/fd` and
`/proc/[pid]/ns`. Denying them would not confine anything, since the thread
already holds the descriptor; it would only make reopening a pipe, a memfd or
the process's own stdio impossible under *any* domain, including one whose
rules have nothing to do with them.

Linux arrives at the same answer twice over: `is_nouser_or_private()` allows
`SB_NOUSER` superblocks up front, and the ancestry walk in
`is_access_to_paths_allowed()` allows when it reaches a disconnected root on an
`MNT_INTERNAL` mount. In gVisor both sets are exactly the mounts created with
`MountOptions.InternalMount`, so one check covers them.

Note that this is not the same as `GetFilesystemOptions.InternalMount`, which
says only that a `GetFilesystem()` call did not come from `mount(2)`. A mount can
be disconnected without being internal — a bind mount clone, for instance — and
those stay subject to the policy.

### POSIX message queues are not exempt

The mount that `mq_open(2)` opens through is disconnected too, but it is *not*
an internal mount, and must not become one: mqueue is a mountable filesystem, so
a rule can name it. `mq_open(2)` is therefore checked like any other open, and a
domain that handles `READ_FILE` or `WRITE_FILE` denies it unless a rule names
the queue or the mqueue root — which requires mqueue to be mounted somewhere the
thread can name, conventionally `/dev/mqueue`.

Linux behaves the same way, though it takes a longer route to get there. The
mqueue superblock is not `SB_NOUSER`, so the up-front exemption does not apply,
and the walk hits `dentry == mnt->mnt_root` before it could reach the
`MNT_INTERNAL` allow branch; `follow_up()` then fails, because the IPC
namespace's mqueue mount has no mount point, and the walk ends undecided. The
root inode is consulted on the way, so a rule added on a `/dev/mqueue` mount of
the same superblock does grant access.

`mq_open(2)` does not go through `VirtualFilesystem.OpenAt()`, so
`mqfs.RegistryImpl` performs the check itself, in `newFD()`, after the DAC check
that `Get()` makes and before the file description is created. The `Dentry` it
builds for the file description has no parent, so the check uses
`LandlockDomain.CheckAccessDetached()`, which is given the queue's identity
along with the registry root to walk up from. A denied `mq_open(2)` with
`O_CREAT` still leaves the queue created, as it does on Linux, where
`do_create()` has already run `vfs_mkobj()` by the time `dentry_open()` is
refused.

### Required rights per operation

`landlockOpenAccessRights()` (Linux: `get_required_file_open_access()`) derives
the rights an open needs from the resulting file mode:

*   The mode is the one `OPEN_FMODE()` derives from the access mode as
    `((flags + 1) & O_ACCMODE)`, so `O_RDONLY` → `READ_FILE`, `O_WRONLY` →
    `WRITE_FILE` and `O_RDWR` → both. The fourth access mode, the one `open(2)`
    accepts as `O_ACCMODE` itself, yields a file that is neither readable nor
    writable and therefore requires no right at all. Switching on the access
    mode rather than on the resulting mode would give that mode whatever the
    default arm grants.
*   A file that is readable and is a directory requires `READ_DIR` and nothing
    else — Linux returns from inside the read arm without consulting the write
    bit, because a directory can only be opened for reading.
*   `EXECUTE` is required *in addition to*, not instead of, what the access mode
    implies. `execve(2)` opens with `O_RDONLY`, so Linux requires `READ_FILE`
    too. Returning `EXECUTE` alone would let a domain that handles `READ_FILE`
    but not `EXECUTE` execute anything, since no layer would then handle any
    requested right.

`landlockModeAccess()` (Linux: `get_mode_access()`) maps a file type to the
`MAKE_*` right needed to create it; a zero mode is treated as `S_IFREG`.
`landlockRemoveAccess()` (Linux: `maybe_remove()`) yields `REMOVE_DIR` for a
directory and `REMOVE_FILE` otherwise.

## Where the checks are made

Checks are made by the `FilesystemImpl`s, through methods on
`vfs.ResolvingPath` — **not** by VFS itself.

This is the central design decision of the change. A check must be evaluated
against the very dentry the operation acts on. VFS has only a pathname, so a
check it performed itself would have to resolve that pathname a second time, and
the two resolutions can disagree: Landlock's threat model is a sandboxed thread
whose siblings are hostile, and a sibling is free to swap a symlink or rename a
component in between. Linux has the same requirement and meets it the same way,
by calling the LSM hooks from inside `fs/namei.c` with the resolved dentry in
hand rather than from the syscall entry point with the pathname.

So where a check falls differs by operation, mirroring the hook Linux uses:

| Method on `ResolvingPath`  | Checked against  | Linux hook                                     |
| -------------------------- | ---------------- | ---------------------------------------------- |
| `CheckLandlockOpen`        | the file itself  | `hook_file_open()`                             |
| `CheckLandlockOpenCreate`  | the parent dir   | `hook_path_mknod()` + `hook_file_open()`       |
| `CheckLandlockCreate`      | the parent dir   | `hook_path_mkdir/mknod/symlink()`              |
| `CheckLandlockRemove`      | the parent dir   | `hook_path_unlink/rmdir()`                     |
| `CheckLandlockRefer`       | the parent dir   | `current_check_refer_path()`                   |
| `CheckLandlockMount`       | n/a (deny)       | `hook_sb_mount()` and friends                  |

The rules for callers:

*   **Open of an existing file** is checked once the file is resolved, and
    **before `O_TRUNC` is honored**, so a denied open leaves the file as it was.
    Linux gets this from `security_file_open()` running inside
    `do_dentry_open()`, which precedes `handle_truncate()` in `do_open()`.

*   **Create, remove, rename and link** are checked **while the implementation
    still holds the lock under which it resolved the parent directory**. Holding
    the lock is what makes the check and the operation agree on what the final
    component names.

*   For an open that creates, `CheckLandlockOpenCreate()` requires
    `MAKE_REG` unioned with the rights the access mode implies, both evaluated
    against the parent. The file does not exist yet, so no rule names it and its
    ancestry is its parent's; because both draw on the same ancestry, requiring
    the union in one walk accepts exactly the same operations as two separate
    checks.

*   Placement within each implementation follows Linux's, so error precedence is
    preserved. For `unlink(2)` and `rmdir(2)` that ordering is, from `do_rmdir()`
    and `do_unlinkat()` in `fs/namei.c`:

    1.  `mnt_want_write()` — `EROFS`,
    2.  the lookup of the victim — `ENOENT`,
    3.  `filename_unlinkat()`'s trailing-slash check, whose comment reads *"Why
        not before? Because we want correct error value"* — `EISDIR` or
        `ENOTDIR`,
    4.  **`security_path_unlink()` / `security_path_rmdir()`** — Landlock's
        `EACCES`,
    5.  `may_delete()`, reached only from inside `vfs_unlink()` and
        `vfs_rmdir()` — the sticky bit's `EPERM`, and `EISDIR`/`ENOTDIR` for a
        victim of the wrong type,
    6.  the filesystem's own removal — `ENOTEMPTY`.

    So `rmdir(2)` of a non-empty directory the policy does not cover reports
    `EACCES`, not `ENOTEMPTY`, while `unlink("d/")` on a directory reports
    `EISDIR` and unlinking a name that does not exist reports `ENOENT` even
    when the policy would also have denied them. Landlock does not hide the
    existence of files from a sandboxed thread; upstream accepts that.

    `rename(2)` follows the same shape — `security_path_rename()` is the last
    thing `filename_renameat2()` does before `vfs_rename()` — and is spelled out
    under [`rename(2)` and `link(2)`](#rename2-and-link2) below.

### `CheckOpenFileType`

Linux rejects some opens in `do_open()`/`may_open()`, *before* the
`security_file_open()` that the Landlock open hook rides on: `ELOOP` for a
symlink, `EISDIR` for a directory opened with `O_CREAT` or for writing.
`vfs.CheckOpenFileType()` factors those out so every `FilesystemImpl` can run
them immediately before `CheckLandlockOpen()`. Without it, a file that could
never be opened at all would report `EACCES` to a sandboxed thread where Linux
reports why.

Everything else an open can fail with stays where each implementation had it,
including rejections Linux makes *after* `security_file_open()` (e.g. `EINVAL`
for `O_DIRECT` on a directory).

### Coverage

tmpfs, gofer, overlay, kernfs and erofs implement the checks. kernfs covers
proc, sys, devpts, cgroupfs, mqfs, nsfs, fuse, host, pipefs and sockfs, none of
which override the relevant `FilesystemImpl` methods — though nsfs, host,
pipefs and sockfs live on internal mounts, so the checks exempt them before any
of that machinery runs. anonfs resolves nothing
and refuses every operation the checks guard. erofs needs only the open hook,
because every other operation on it fails with `EROFS`.

> A `FilesystemImpl` that resolves paths and does not call these methods is not
> checked. Any new one must call them.

Two implementations needed structural changes to make room for the check. In
both gofer and overlay, `doCreateAt()` gained a `checkLandlock func(parent
*dentry) error` callback, invoked with the parent's lock held, once the file is
known not to exist, and — for overlay — before the parent is copied up, so that
a denied create has no effect at all.

## `rename(2)` and `link(2)`

ABI v1 has no `LANDLOCK_ACCESS_FS_REFER` right, which makes these the subtlest
part of the implementation. `CheckLandlockRefer()` matches
`current_check_refer_path()`:

*   **Cross-directory is always refused** whenever a domain is active — even a
    domain that handles no relevant rights, and even between two directories
    the policy fully allows. There is simply no right in v1 that can authorize
    reparenting; `REFER` is denied by default even to a domain that does not
    handle it.

    *Which* error says so still depends on the policy, because
    `current_check_refer_path()` prioritizes `EACCES` over `EXDEV`. The rights
    the operation would need anyway are checked first, each against its own
    directory — the source directory needs `REMOVE_<src>` for a rename (and
    `MAKE_<replaced>` under `RENAME_EXCHANGE`), the destination directory needs
    `MAKE_<src>` and, if it is replacing a file, `REMOVE_<replaced>`. If either
    is denied the answer is `EACCES`; `EXDEV` is reserved for the case where
    the only missing right is `REFER`. The comment on that function explains
    why: it lets a caller tell "there is no way to do this" apart from "copy
    the file to the destination instead".

*   **Same-directory** operations are permitted if the domain grants the
    required rights in that directory:

    | Operation                             | Rights required                                 |
    | ------------------------------------- | ----------------------------------------------- |
    | `link(2)`                             | `MAKE_<type of source>`                          |
    | `rename(2)`                           | `MAKE_<src>` + `REMOVE_<src>`                    |
    | `rename(2)` over an existing file     | ... + `REMOVE_<type of replaced file>`           |
    | `rename(2)` with `RENAME_EXCHANGE`    | ... + `MAKE_<type of replaced file>`             |

    The `Removable` field distinguishes them: `rename(2)` detaches the source
    from its directory, `link(2)` does not. So a same-directory link needs only
    `MAKE_*`, while a rename also needs `REMOVE_*`.

*   The required right depends on the **type of the file being moved**: a
    symlink needs `MAKE_SYM`, a directory `MAKE_DIR | REMOVE_DIR`.

*   `RENAME_NOREPLACE` over an existing destination reports `EEXIST`, not the
    Landlock error. Linux's `do_renameat2()` rejects it before reaching
    `security_path_rename()`, so `EEXIST` is not masked by `EXDEV` or `EACCES`.

*   Everything else `rename(2)` can fail with is checked by `vfs_rename()`,
    which `filename_renameat2()` calls immediately *after*
    `security_path_rename()`. So the hook runs after the parent lookups, the
    `EXDEV`, the `EBUSY` for `.`/`..`, the `EROFS` from `mnt_want_write()`, the
    child lookups with their `RENAME_NOREPLACE` `EEXIST`, and the trailing-slash
    `ENOTDIR` — and *before* the permission and sticky-bit checks in
    `may_delete()`, the `EISDIR`/`ENOTDIR` type mismatches, the `EMLINK` link
    limit and the filesystem's own `ENOTEMPTY`. Renaming a directory over a
    non-empty one under a domain that refuses it therefore reports `EACCES`, not
    `ENOTEMPTY`, which would otherwise disclose the contents of a directory the
    policy hides.

*   `link(2)` is bracketed the same way. `do_linkat()` checks `EXDEV` and then
    calls `may_linkat()` — the `protected_hardlinks` check — *before*
    `security_path_link()`, and reaches `vfs_link()`'s `EPERM` for a directory,
    `ENOENT` for a source with no links left and `EMLINK` only *after* it. So
    linking an unsafe source reports `EPERM` even under a domain that would also
    have refused the link, while linking a directory reports `EACCES`.

*   When the source is a filesystem root and so has no parent, `OldParent` is
    left nil and the operation is treated as crossing directories.

These semantics were established by probing a real kernel rather than by reading
the source alone; two initially plausible assumptions (that cross-directory
would be allowed when no relevant rights are handled, and that link and rename
require the same rights) turned out to be wrong.

## Mount operations

`mount(2)`, `umount2(2)`, `pivot_root(2)` and `move_mount(2)` return `EPERM`
whenever a domain is active. Where the denial sits among the other errors these
calls can return follows Linux, which resolves the paths first and only then
runs the hook, so a malformed call still reports what is wrong with it:

*   `mount(2)`, `pivot_root(2)` and `move_mount(2)` call
    `vfs.CheckLandlockMountAt()`, which resolves the paths that Linux resolves
    ahead of the hook — the mount point for `mount(2)`, both directories for the
    other two — and reports the first resolution failure instead of the denial.
    Only a call whose paths all resolve is denied. The paths are walked only
    when a domain is active, so an allowed call still walks each of them once,
    in the operation itself. For `mount(2)` the check precedes the dispatch on
    flags, so it covers `MS_REMOUNT`, `MS_BIND` and `MS_MOVE` alike, and it also
    precedes the `EINVAL` that gVisor returns for the flags it does not
    implement, which Linux does not return at all.
*   `umount2(2)` is checked inside `vfs.VirtualFilesystem.UmountAt()`, after the
    mount to unmount has been found and before the busy check. Linux runs this
    one hook late: `do_umount()` calls `security_sb_umount()`, and `can_umount()`
    has already rejected a path that names no mount of ours with `EINVAL`.

The `CAP_SYS_ADMIN` check sits before the denial in gVisor and after it in
Linux, where `path_mount()` calls `security_sb_mount()` before `may_mount()`.
Both report `EPERM`, so the order is not observable.

`fsconfig(2)` with `FSCONFIG_CMD_RECONFIGURE` reconfigures a superblock, which
is what `MS_REMOUNT` does through the older interface, and is refused the same
way. That one is checked in `fsconfigfd.Fd.DoCmdReconfigure()` rather than at
the syscall entry, so that the wrong-phase `EBUSY` and the `CAP_SYS_ADMIN`
`EPERM` still come first: Linux reaches `security_sb_remount()` from
`reconfigure_super()`, which `vfs_cmd_reconfigure()` only calls once it has made
both of those checks. The domain consulted is the calling thread's, not the one
captured when the descriptor was opened. `FSCONFIG_CMD_CREATE` and `fsmount(2)`
need no check, matching Linux, which hooks only the operations that change the
mount tree.

Landlock has no right that can grant these, so they are refused outright. This
is also what keeps the rest of the policy meaningful: a thread that could
rearrange the mount tree could bring a file it is allowed to access into a path
it is not, or hide one behind a mount of its own.

## ABI details

`pkg/abi/linux/landlock.go` holds the UAPI constants and structs.

`LandlockPathBeneathAttr` is `__attribute__((packed))` in Linux, 12 bytes rather
than the 16 Go's alignment rules give it. Its last field is tagged
`marshal:"unaligned"` so the marshalled form drops the trailing padding and
matches the wire size.

`landlock_create_ruleset(2)` accepts a `size` argument, so userspace built
against an older or newer header can call it. Following
`copy_min_struct_from_user()`: a struct shorter than the sentry's is zero-filled
in its missing trailing fields; a longer one is accepted only if its extra bytes
are all zero, and is `E2BIG` otherwise. Validation of `HandledAccessNet` and
`Scoped` therefore only rejects rights the caller actually asked for.

`LANDLOCK_CREATE_RULESET_VERSION` returns 1.
`LANDLOCK_CREATE_RULESET_ERRATA` returns 4, the bit for erratum 3, which the
ancestry walk implements. It is the only erratum that applies to ABI 1; the
others apply to ABI versions above the one implemented here, and Linux does not
report those on an ABI 1 kernel either.

`landlock_add_rule(2)` rejects a parent FD that is a ruleset FD or that lives on
an internal mount — anonfs, pipefs, sockfs, nsfs, the tmpfs behind
`memfd_create(2)` and SysV shm, and the host mount holding donated host FDs —
with `EBADFD`, matching the `MNT_INTERNAL` /
`SB_NOUSER` rejections in `get_path_from_fd()`. Those are the same mounts the
policy exempts, so a rule naming one could never match. It rejects
directory-only rights
on a non-directory. `ENOMSG` is returned for an empty access mask, `EINVAL` for
rights the ruleset does not handle.

`landlock_restrict_self(2)` requires `no_new_privs` or `CAP_SYS_ADMIN`, and
checks for it before it looks at anything the caller passed, so a thread that
may not sandbox itself gets `EPERM` even when its flags or its descriptor are
also bad. Linux moved the check there in commit eba39ca4b155 ("landlock: Change
`landlock_restrict_self(2)` check ordering").

## Limitations

The syscalls are registered as `PartiallySupported` at 444–446 on AMD64 and
ARM64. What is not implemented:

*   **ABI versions above 1.** `LANDLOCK_ACCESS_FS_REFER` (v2),
    `LANDLOCK_ACCESS_FS_TRUNCATE` (v3), network rights (v4),
    `LANDLOCK_ACCESS_FS_IOCTL_DEV` (v5) and IPC scoping (v6) are all rejected at
    ruleset creation. `LANDLOCK_RULE_NET_PORT` is rejected by
    `landlock_add_rule(2)`.
*   **Inode-number reuse** within a single gofer-backed filesystem, described
    above.

## Testing

*   `test/syscalls/linux/landlock_v1.cc` — 98 syscall test cases, each written
    against native Linux first and then run under runsc. Coverage includes the
    ABI surface, every right, the rights each `open(2)` access mode requires,
    layering, inheritance across `fork(2)`, rename/link semantics, the errno each
    denial reports and where it sits among the other errors the operation can
    return, mount denial including `fsconfig(2)` reconfiguration, `mq_open(2)`,
    rules reached through hard links, bind mounts and renamed directories, and
    overlay copy-up.

    Two cases swap a symlink out from under a path while a create or an unlink
    runs. They assert only that nothing ever landed in the directory the policy
    does not cover, so a run that never wins the race still passes. They disable
    cooperative save while running: the save/restore variants checkpoint at every
    syscall the test helpers make, which would decide the race for them.

*   `pkg/sentry/vfs/landlock_test.go` — Go unit tests for the domain evaluation
    logic that syscall tests cannot isolate: mask arithmetic, layer stacking and
    the layer limit, rule unioning, rules following the file, and the
    open-rights derivation.

*   `pkg/sentry/fsimpl/overlay/overlay_test.go` — a Go unit test that a pinned
    identity survives copy-up, asserting on the way that the dentry really was
    reinstantiated from the upper layer alone, which a syscall test cannot
    observe.

Verified on native, `runsc_ptrace`, `systrap_shared`, `systrap_directfs`,
`systrap_overlay` and the `save_resume` variant of each, plus the VFS, tmpfs,
gofer, kernfs, overlay and auth unit suites.

## Adding Landlock support to a new filesystem

1.  Implement `DentryImpl.InodeIdentity()`. Pick an `ino` that is unique within
    the filesystem and stable across dentry eviction. A pointer to a cached
    per-inode structure is *not* valid.
2.  Implement `FilesystemImpl.WalkAncestors()`, usually by delegating to
    `genericfstree.WalkAncestors`.
3.  Call the `ResolvingPath.CheckLandlock*` methods from `OpenAt`, `MkdirAt`,
    `MknodAt`, `SymlinkAt`, `UnlinkAt`, `RmdirAt`, `LinkAt` and `RenameAt`, at
    the points described in [Where the checks are made](#where-the-checks-are-made)
    — with the parent's lock held, and before any side effect.
4.  Call `vfs.CheckOpenFileType()` immediately before `CheckLandlockOpen()`.

## References

*   `security/landlock/` in the Linux source, particularly `fs.c`, `ruleset.c`
    and `syscalls.c`. Doc comments throughout the sentry implementation name the
    specific Linux function each piece matches.
*   landlock(7), landlock_create_ruleset(2), landlock_add_rule(2),
    landlock_restrict_self(2).
*   https://landlock.io/
