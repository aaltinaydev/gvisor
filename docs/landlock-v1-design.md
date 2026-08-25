# Landlock ABI v1 in gVisor

This document explains the "Implement Landlock ABI v1" change: what the
Landlock v1 ABI is, how gVisor's filesystem layer is structured, how the
implementation maps Landlock's semantics onto that structure, and the design
choices made to keep the behavior faithful to Linux.

All Linux references are against Linux v7.0 (`security/landlock/`), which the
implementation was reviewed against.

---

## 1. The Landlock ABI, version 1

Landlock is Linux's unprivileged application-sandboxing LSM. A process can
voluntarily and irrevocably restrict its *own* filesystem access (and that of
all its future children) without needing any privilege. It is exposed as three
syscalls:

- **`landlock_create_ruleset(attr, size, flags)`** (444) — creates a *ruleset*
  and returns it as a file descriptor. `attr->handled_access_fs` is a bitmask
  of the access rights this ruleset *handles*: every handled right becomes
  **deny-by-default** and must be re-granted by explicit rules. With
  `flags=LANDLOCK_CREATE_RULESET_VERSION` the call instead returns the highest
  supported ABI version, and with `LANDLOCK_CREATE_RULESET_ERRATA` a bitmask
  of fixed errata — the mechanism userspace uses for best-effort fallback
  across kernels.
- **`landlock_add_rule(ruleset_fd, rule_type, attr, flags)`** (445) — adds a
  rule to a ruleset. ABI v1 has one rule type, `LANDLOCK_RULE_PATH_BENEATH`:
  an open FD to a file or directory plus an `allowed_access` bitmask. The rule
  grants those rights to that object and (for directories) **everything
  beneath it**.
- **`landlock_restrict_self(ruleset_fd, flags)`** (446) — enforces the ruleset
  on the calling thread. Requires `no_new_privs` (or `CAP_SYS_ADMIN` in the
  caller's user namespace). Each call stacks a new *layer* onto the thread's
  *domain*; up to 16 layers can be stacked, and an access is allowed only if
  **every** layer that handles it allows it.

```
  landlock_create_ruleset({handled_access_fs: READ_FILE|WRITE_FILE})
        │
        ▼
  ┌──────────────────────┐    landlock_add_rule(fd, PATH_BENEATH,
  │ Ruleset (held as FD) │        {parent_fd: <fd of /var/data>,
  │  handled: R|W        │◄───     allowed_access: READ_FILE})
  │  rules:              │
  │   /var/data → R      │
  └──────────┬───────────┘
             │ landlock_restrict_self(fd)      (requires no_new_privs)
             ▼
  Thread's domain — an immutable stack of layers (max 16):
  ┌────────────────────────────────┐
  │ Layer 2: handles R|W           │ ← snapshot of this ruleset
  │    /var/data → READ_FILE       │
  ├────────────────────────────────┤
  │ Layer 1: handles W             │ ← from an earlier restrict_self
  │    /tmp → WRITE_FILE           │
  └────────────────────────────────┘
  An access is allowed ⇔ EVERY layer that handles it grants it.
```

ABI v1 defines 13 filesystem access rights: `EXECUTE`, `WRITE_FILE`,
`READ_FILE`, `READ_DIR`, `REMOVE_DIR`, `REMOVE_FILE`, and the seven `MAKE_*`
rights (`REG`, `DIR`, `CHAR`, `BLOCK`, `FIFO`, `SOCK`, `SYM`). Notably *not*
in v1: `TRUNCATE` (v3), `IOCTL_DEV` (v5), network rules (v4), and IPC scoping
(v6) — under v1 those operations are simply unrestricted.

Two v1 semantics are easy to get wrong and are worth calling out:

- **Cross-directory rename/link always fails with `EXDEV`.** Linking or
  renaming a file into a *different* directory re-parents it, which changes
  what a `path_beneath` rule covers. The `REFER` right that permits this only
  exists from ABI v2; internally Linux ORs an always-denied `REFER` into every
  v1 layer (`_LANDLOCK_ACCESS_FS_INITIALLY_DENIED`), so for any v1 domain a
  cross-directory rename/link can never succeed — it fails `EXDEV`, or
  `EACCES` if the required rights on the involved parents are missing (the
  `EACCES` checks run first).
- **Beyond file access, a domain also restricts topology and observation.**
  A landlocked task cannot `mount`, `umount`, `move_mount`, `pivot_root`, or
  reconfigure filesystems (`EPERM`), and cannot `ptrace` (or otherwise
  observe, e.g. via `/proc/<pid>/environ`) a task outside its own domain
  hierarchy — a tracer's domain must be an ancestor of (or equal to) the
  tracee's.

gVisor reports ABI version **1** and errata value **4**: erratum 3
("disconnected directory handling", applicable to ABI 1, landed in Linux
v6.19) is genuinely implemented by the ancestor-walk logic described below.

---

## 2. gVisor's filesystem layer in a nutshell

gVisor's sentry is a userspace kernel: the sandboxed application's syscalls
are handled entirely inside the sentry, which implements its own VFS
(`pkg/sentry/vfs`).

```
  Application syscall (open / mkdir / rename / ...)
        │
  ┌─────▼──────────────────── Sentry ─────────────────────────────┐
  │  VirtualFilesystem  (mount tree, syscall entry points)        │
  │        │ builds a ResolvingPath, dispatches to the fs impl    │
  │        ▼                                                      │
  │  FilesystemImpl — walks the path ITSELF, under its own locks  │
  │  (permission and Landlock checks happen in here)              │
  │  ┌───────┐ ┌───────┐ ┌────────────────────┐ ┌─────────┐       │
  │  │ gofer │ │ tmpfs │ │ kernfs: procfs,    │ │ overlay │  ...  │
  │  │       │ │       │ │ sysfs, fuse, mqfs… │ │ erofs   │       │
  │  └───┬───┘ └───────┘ └────────────────────┘ └─────────┘       │
  └──────┼────────────────────────────────────────────────────────┘
         │ LISAFS messages / directfs FDs
         ▼
   host filesystem (via the gofer process or direct host FDs)
```

The key objects:

- **`VirtualFilesystem`** — the top-level object; owns the mount tree and the
  entry points (`OpenAt`, `MkdirAt`, `RenameAt`, ...).
- **`Mount` / `MountNamespace`** — a mounted filesystem instance at a location
  in the tree.
- **`FilesystemImpl`** — the per-filesystem-type implementation interface.
  Unlike Linux, where the VFS itself walks paths and calls small per-fs
  callbacks, gVisor delegates most of each operation — *including the path
  walk* — to the `FilesystemImpl`, driven by a **`ResolvingPath`** object that
  encodes the remaining path, symlink budget, and mount-crossing state. This
  means per-operation checks (permissions, and now Landlock) largely live
  *inside* each filesystem implementation, under its own locks.
- **`Dentry`** — a node in a filesystem's tree. gVisor has no unified inode
  object at the VFS layer; inode-like state is private to each impl.

### The filesystem implementations touched by this change

- **gofer** (`fsimpl/gofer`) — the workhorse: provides the container's root
  and bind mounts, backed by host files accessed via LISAFS messages to an
  external gofer process, or directly via `directfs`. Caches dentries, may
  evict them under memory pressure, and synthesizes sentry inode numbers
  (`inoByKey`) from host `(device, inode)` keys.
- **tmpfs** (`fsimpl/tmpfs`) — fully in-sentry RAM filesystem; `/tmp`,
  `/dev/shm`, and various runtime mounts.
- **kernfs** (`fsimpl/kernfs`) — a framework (analogous to Linux's kernfs) for
  kernel-generated trees; **procfs, sysfs, devpts, cgroupfs, mqfs, fuse, and
  host** are all built on it, sharing its generic path-walk and operation
  code.
- **overlay** (`fsimpl/overlay`) — overlayfs; merges lower layer(s) with an
  upper layer, copying files up on first write.
- **erofs** (`fsimpl/erofs`) — read-only EROFS images (used for rootfs
  delivery in some deployments).
- **fuse** (`fsimpl/fuse`) — FUSE servers running inside the sandbox; built on
  kernfs.
- **host** (`fsimpl/host`) — wraps individual host FDs imported into the
  sandbox (stdio, sockets); a flat, internal filesystem with no real tree.
- **mqfs** (`fsimpl/mqfs`) — POSIX message queues (`mq_open` and the
  `/dev/mqueue` view of them); kernfs-based.
- **pipefs, sockfs, nsfs, anonfs** — internal "virtual" filesystems that give
  pipes, sockets, namespace FDs, and anonymous FDs an identity for
  `/proc/*/fd` purposes. They have no user-visible mount.

---

## 3. How Landlock v1 is implemented in gVisor

### Rulesets, domains, and the access check

The core lives in `pkg/sentry/vfs/landlock.go`:

- A **`LandlockRuleset`** holds `handledAccessFS` and a rule map keyed by
  **`InodeIdentity`** (see below). It is exposed to the task as an anonymous
  FD (`LandlockRulesetFileDescription`), matching Linux's ruleset-FD model,
  including the FD-mode gymnastics (`landlock_add_rule` requires the FD to be
  writable, `landlock_restrict_self` requires it readable).
- A **`LandlockDomain`** is an immutable stack of layers plus a `parent`
  pointer to the domain it was derived from. `landlock_restrict_self` never
  mutates a domain: it snapshots the ruleset's rules and produces a *new*
  domain via `Merge` (capped at 16 layers, `E2BIG` beyond). The parent chain
  exists purely for ptrace scoping.
- The domain hangs off **`auth.Credentials.LandlockDomain`**. Credentials in
  gVisor are copy-on-write values copied on `fork` and preserved across
  `execve` and UID changes, so Landlock's inheritance semantics (children and
  execve'd programs stay confined; the domain is per-thread until inherited)
  fall out for free, exactly as Linux's `cred`-attached domain does.

An access check (`LandlockDomain.checkAccess`) mirrors Linux's
`landlock_check_access` layer-mask algorithm: build a per-layer mask of the
requested rights each layer handles, then walk from the target dentry up
through its ancestors — crossing mount boundaries — unmasking rights granted
by any rule that matches a visited node's identity. The access is allowed only
when every layer's mask empties; otherwise `EACCES`.

```
  open("/a/b/f", O_RDONLY) under a 2-layer domain → need READ_FILE

  per-layer masks = rights still unsatisfied:
    start:                L1={READ_FILE}   L2={READ_FILE}

  ancestor walk:  f ──► b ──► a ──► /
    at f:  no rule matches       L1={READ_FILE}  L2={READ_FILE}
    at b:  L1 rule grants R      L1={}           L2={READ_FILE}
    at a:  L2 rule grants R      L1={}           L2={}
                                  └── all masks empty → ALLOW
  (any mask still nonempty after reaching "/" → EACCES)
```

The ancestor walk is `VirtualFilesystem.WalkAncestors`
(`pkg/sentry/vfs/ancestry.go`), a new VFS primitive: each `FilesystemImpl`
provides its own `WalkAncestors` (most reuse a shared `genericfstree`
implementation that walks the dentry `parent` chain under the filesystem's
ancestry lock), and the VFS-level wrapper stitches filesystems together by
hopping to the mount point when a walk reaches a mount root — the same shape
as Linux's `follow_up` loop, including the subtle detail that Linux **skips
the mountpoint dentry itself** after crossing upward (handled by the
`crossed` flag).

### Hook placement: inside the filesystem implementations

Because gVisor's path resolution happens inside each `FilesystemImpl`, the
Landlock checks cannot be a wrapper at the `VirtualFilesystem` entry points —
they must run at the same point in each operation where Linux runs its LSM
hooks, so that error *ordering* (which check fires first) matches Linux.
`ResolvingPath` therefore grew a family of check helpers that the fsimpls call
mid-operation:

- `CheckLandlockOpen` / `CheckLandlockOpenCreate` — `open(2)`; the access
  rights are derived from the open flags exactly as Linux does (read on a
  directory → `READ_DIR`; `O_CREAT` of a new file additionally requires
  `MAKE_REG` on the parent). Open modes not covered by v1 (e.g. `O_PATH`,
  `O_TRUNC`'s truncation, ioctls) remain unrestricted.
- `CheckLandlockCreate` — `mkdir`, `mknod`, `symlink`; the required `MAKE_*`
  right is derived from the new node's file type.
- `CheckLandlockRemove` — `unlink`/`rmdir` (`REMOVE_FILE`/`REMOVE_DIR` on the
  parent).
- `CheckLandlockRefer` — `rename`/`link`. Implements the full v1 matrix:
  required rights on the old parent (removal of the source; for
  `RENAME_EXCHANGE`, also creation of the destination's type) and the new
  parent (creation of the source's type; removal of a replaced destination),
  checked in Linux's order so `EACCES` takes priority — and if both parents
  differ and all rights checks pass, unconditional `EXDEV`, since no v1 layer
  can ever grant `REFER`.

These hooks were threaded into **gofer, kernfs (and thus procfs/sysfs/devpts/
fuse/host/cgroupfs), overlay, tmpfs, and erofs** at each create/open/remove/
rename/link site. mqfs gets a special-cased open check (below). In several
places the surrounding code was *reordered* to match Linux's errno precedence
— see §4.

The mount-topology and ptrace restrictions live outside the fsimpls:
`mount`/`move_mount`/`umount`/`pivot_root`/`fsconfig`-reconfigure call
`CheckLandlockMount*` (returning `EPERM` for any landlocked task, but only
after resolving the involved paths so path errors keep priority), and
`Task.CanTrace` gained a `LandlockCanPtrace` check: the tracer's domain must
appear on the tracee's domain parent chain (`ScopeLE`). This also covers the
indirect observation paths that funnel through `CanTrace`, such as
`/proc/<pid>/environ`.

```
  Domains form a tree via their parent pointers:

     (unrestricted) ── D1 ── D2 ── D3        D2' (parent: D1)

  tracer allowed to trace a task in D3 ⇔ tracer's domain is on
  D3's parent chain (or the tracer is unrestricted):
     unrestricted → allowed        D2  → allowed (ancestor)
     D3           → allowed (same) D2' → DENIED  (sibling branch)
```

### The syscall layer

`sys_landlock.go` implements the three syscalls with Linux's exact validation
order, including the subtle cases verified against v7.0: `EFAULT` for a null
attr before size checks and `E2BIG` for oversized attrs with nonzero trailing
bytes in `create_ruleset` (the standard `copy_struct_from_user` contract);
`ENOMSG` for empty handled/allowed masks; `EINVAL` for rights outside the v1
mask or file-only rights on a non-directory rule target; `EBADFD` for
non-ruleset FDs (including using a ruleset FD *as* a rule target) and for
rule targets on internal mounts; and `EPERM`-before-`EINVAL` in
`restrict_self` (the `no_new_privs` check precedes flag validation).

---

## 4. Design choices made for correctness

### `InodeIdentity` instead of object pointers

Linux keys rules on a `landlock_object` that wraps a `struct inode *`. gVisor
has no VFS-layer inode, and dentries are not stable handles (gofer evicts
them). Rules are instead keyed by an **`InodeIdentity`** value: `(filesystem
ID, inode number)`. Inode numbers are only unique within a `vfs.Filesystem`
instance, so the filesystem ID — a monotonic per-instance counter that is
never reused — is what prevents two different filesystem instances that
happen to expose the same inode number from aliasing each other's rules. The
device numbers a filesystem reports in `stat` add nothing to the key: every
identity producer derives them from the filesystem instance the inode belongs
to, so they are a function of the filesystem ID, not a discriminator within
it. Each `DentryImpl` must produce its identity; implementations
that cannot (or should not) participate return the zero identity, which by
construction never matches any rule.

### Pinning rule targets: the `landlock_object` analog

Keying rules by value creates a lifetime problem that Linux solves by
refcounting the inode: the identity must keep meaning the same file for as
long as the rule exists.

- **gofer**: sentry inode numbers are synthesized on first lookup and the
  cache (`inoByKey`) is not saved across checkpoint/restore — worse, gofer's
  `PrepareSave` evicts every cached dentry. Without countermeasures, any rule
  whose target had no open FD would stop matching after a restore (silently
  turning everything beneath it into `EACCES`), or after cache eviction could
  even start matching an unrelated file that was assigned a recycled ino.
  gofer therefore implements **`PinInodeIdentity`**: when a rule is added,
  the target dentry takes a reference and is recorded in a pinned set —
  the direct analog of Linux's `landlock_object` inode pin. Pins are released
  at filesystem teardown, and pins on *deleted* files are released at save
  time (their inos have already been retired via `releaseInoOnDeletion`, so
  those rules correctly never match again — matching Linux, where a rule on
  an unlinked inode is dead).
- **overlay**: identity must survive **copy-up**, or a rule added on a
  lower-layer file would stop matching the moment the file is first written.
  Overlay derives identity from the *lowest* layer when one exists, and for
  pinned lower identities records an `upper → origin` mapping at copy-up time
  so the post-copy-up dentry still reports its original identity. This mirrors
  Linux, where overlayfs exposes a stable inode across copy-up. Pinning an
  overlay dentry also pins the layer dentries its identity is derived from:
  layer inode numbers (gofer's in particular) are only stable across
  save/restore while the layer dentry stays alive, and runsc's default
  rootfs is an overlay with a gofer lower layer.

  ```
    rule added on a lower-layer file          first write → copy-up
    ┌─ upper ─┐                               ┌─ upper ─┐
    │   (—)   │                               │  file'  │ identity U
    ├─ lower ─┤                               ├─ lower ─┤
    │  file   │ identity L                    │  file   │ identity L
    └─────────┘                               └─────────┘
    InodeIdentity() = L                       InodeIdentity() =
    (rule keyed on L)                           identityOrigins[U] → L
                                              → the rule still matches
  ```
- **tmpfs/kernfs/erofs**: dentries and inode numbers are stable for the life
  of the filesystem, so no pinning is needed (the pinner interface is
  optional).

### Errno ordering: hooks placed *and* code reordered to match Linux

Landlock is observable not just through allow/deny but through *which* error
userspace sees. Several operations were restructured so gVisor's check order
matches `namei.c` + the LSM hook points:

- A new `CheckOpenFileType` helper enforces `ELOOP`/`EISDIR` file-type errors
  *before* the Landlock open check, because Linux validates these before
  calling security hooks.
- `unlink`/`rmdir` paths (gofer, tmpfs, kernfs) were restructured to Linux's
  `do_unlinkat` order: walk to the parent → write-permission/`EROFS` →
  lookup of the final component → Landlock → `mayDelete`. kernfs previously
  hoisted `CheckBeginWrite` above the entire walk, which returned `EROFS`
  where Linux returns `ENOENT` for a missing intermediate component.
- `rename` in every fsimpl runs `CheckLandlockRefer` at Linux's hook point,
  with permission checks moved after it where necessary; kernfs's delete
  check was split into structural vs. permission halves so Landlock sits
  between them, and the directory-hardlink `EPERM` moved after the Refer
  check.
- Deny-before-create on `open(O_CREAT)`: gVisor checks
  `MAKE_REG`+open-rights on the parent *before* creating the file. This is a
  **deliberate, documented divergence**: Linux creates the file and then
  fails the open, leaving an empty file behind. gVisor's behavior is strictly
  cleaner and invisible to the denied process (which cannot observe the
  directory either way).
- `mount(2)`'s unsupported-flags `EINVAL` was moved after the Landlock check
  so a landlocked task sees `EPERM`, as on Linux.
- In gofer's `unlinkAt`, the child dentry is force-loaded when Landlock is in
  use (a `landlockInUse` fast-path flag on the `VirtualFilesystem` keeps this
  cost at zero for non-Landlock workloads) because `REMOVE_FILE` vs.
  `REMOVE_DIR` depends on the victim's type.

### Ancestor-walk semantics under fsimpl locks

Two subtleties in `WalkAncestors`:

1. **Mount-crossing fidelity.** After hopping from a mount root to its
   mountpoint, the walk resumes at the mountpoint's *parent* — Linux's
   `follow_up` behaves the same way, and getting this wrong changes which
   rules match around bind mounts.

   ```
     fs A (the "/" mount)          fs B (bind-mounted at /mnt)
     ────────────────────          ───────────────────────────
        /                            (B's root)
        └── mnt  ◄── mountpoint ─────┘└── sub
                                          └── file

     WalkAncestors(file):
       file → sub → (B's root)          # walk inside fs B
         cross the mount: hop to the mountpoint /mnt on fs A,
         but SKIP the /mnt dentry itself (Linux follow_up ditto)
       → /                              # resume at mountpoint's parent
   ``` The walk also visits the mount root even
   when the starting dentry has been disconnected from it (a deleted or
   renamed-over directory), which is exactly erratum 3's "disconnected
   directory" fix — hence the errata value of 4.
2. **Deferred reference dropping.** The check runs *inside* fsimpl operations,
   under filesystem locks. Crossing a mount takes references on the
   mountpoint dentry and mount, and dropping a dentry reference can itself
   acquire locks or perform I/O. References acquired during the walk are
   therefore accumulated in a `toDecRef` list on the `ResolvingPath` and
   released only after the operation ends, avoiding lock-ordering violations.

### Internal mounts are exempt — explicitly

Linux only enforces Landlock on user-visible filesystems; kernel-internal
mounts (pipes, sockets, anonymous inodes) are not restrictable. gVisor makes
this an explicit property: mounts created with `InternalMount: true` (anonfs,
pipefs, sockfs, nsfs, shm, cgroup2's internal mount, and the host mount for
imported FDs) are skipped by `checkAccess` and rejected as rule anchors with
`EBADFD` — the same errno Linux produces for such FDs.

### mqfs: mirroring Linux's mqueue quirk

In Linux, `mq_open` *is* Landlock-restricted, because the internal mqueue
mount shares its superblock with `/dev/mqueue` mounts — a rule on
`/dev/mqueue` governs `mq_open`. gVisor's mqfs replicates this: queue-FD
creation runs an open-style check using the queue inode's identity as a
*detached* leaf anchored at the mqueue mount root (`CheckAccessDetached`),
since the freshly built queue dentry is not attached to the tree at that
point.

### Save/restore

Rulesets, domains, and layers are `+stateify savable`, so a checkpointed
landlocked container restores with its confinement intact. The two pieces
that made this actually work are the gofer pinning above (identities survive
the dentry-cache flush) and retiring inos on deletion so restored rules can
never rebind to recycled inode numbers the sentry knows about.

### Known, deliberate divergences

- The no-empty-file-on-denied-`O_CREAT` behavior described above.
- Pins live until filesystem teardown (and, for deleted files, until save
  time); they are not released when a ruleset FD is closed or a domain
  becomes unreachable, whereas Linux frees a ruleset's `landlock_object`s
  (dropping their inode references) with the ruleset. A sandboxed process
  can therefore keep one gofer dentry alive per distinct file it has ever
  named in `landlock_add_rule`, for the life of the sandbox.
- If a rule's target is unlinked while other hard links to it survive, the
  pin is still dropped at save time even though the inode number is not yet
  retired; after a restore, the rule may stop matching the surviving links
  (fail-closed). Without save/restore, the rule keeps matching all links,
  as in Linux.
- On gofer **shared** mounts, a file deleted *outside* the sandbox (host-side,
  or via a different mount of the same host tree) cannot be attributed to the
  rule pinning it; if the host later reuses that inode number, the stale rule
  could match a new file. This is inherent to not owning the host filesystem
  and is documented in the syscall's `PartiallySupported` note.
- gVisor's procfs returns `EPERM` for `link(2)` into `/proc` where Linux
  fails the new-name lookup with `ENOENT` first — a pre-existing kernfs
  lookup-ordering divergence, not introduced by this change.

---

## 5. Testing

- `test/syscalls/linux/landlock_v1.cc` (~3,400 lines added): a conformance
  suite covering the syscall ABI edge cases, every v1 access right, layer
  stacking, rename/link `EXDEV`/`EACCES` priority, bind-mount and
  disconnected-directory ancestor walks, ptrace scoping, exec inheritance,
  and scenarios ported from the kernel's Landlock selftests. The suite passes
  **natively on Linux** — the primary correctness oracle — and on gVisor's
  directfs, shared, overlay, and ptrace platform variants, including through
  save/restore.
- `pkg/sentry/vfs/landlock_test.go`, `overlay_test.go`, and `gofer_test.go`
  unit-test the layer-mask algorithm, identity stability across copy-up, and
  identity pinning across dentry eviction/save.
