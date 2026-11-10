---
slug: lvm-mounting-support
issue: https://github.com/openrelik/openrelik/issues/40
created: 2026-11-10
by: hacktobeer (Ramses de Beer)
---
# Research: Add LVM2 mounting support

Notes on how to add LVM2 mounting to `openrelik-worker-common`.

## What I wanted to know

1. How `BlockDevice` discovers and mounts filesystems today, and where LVM2 fits.
2. What the LVM2 command sequence is for going from a physical volume to mountable
   logical volumes, and what can go wrong.
3. How other forensic tools expose LVM logical volumes, and what analysts expect.
4. What evidence-integrity and cleanup constraints the change must respect.

## What I found

### 1. Current behaviour

`BlockDevice.setup()` maps the image to a loop or NBD device, reads `lsblk` output
in `_blkinfo()`, and `_parse_partitions()`
(`libs/worker-common/openrelik_worker_common/mount_utils.py:488`) decides what to
mount. A partition is mounted only when `_is_important_partition()` accepts it,
which requires a filesystem type in `supported_fstypes`
(`dos`, `xfs`, `ext*`, `ntfs`, `vfat`, `btrfs`). An LVM2 physical volume reports
type `LVM2_member`, which is not in that list, so both whole-disk and partitioned
LVM images yield no mount targets today.

`_get_fstype()` (`mount_utils.py:563`) runs `blkid -s TYPE -o value`. `blkid` exits
with code 2 both for a device with no filesystem signature and for a device that
does not exist, so the two cases were previously indistinguishable.

### 2. LVM2 mechanics

LVM2 layers block devices: a physical volume (PV) belongs to a volume group (VG),
and the VG is split into logical volumes (LVs) that hold the filesystems. A PV can
be the whole disk or a partition. The minimal read-only recovery sequence is:

```bash
pvs --noheadings -o vg_name /dev/loop0      # which VG the PV belongs to
vgchange -ay <vg_name>                      # activate, making LVs appear
lvs --noheadings -o lv_path <vg_name>       # /dev/<vg>/<lv> paths
blkid -s TYPE -o value /dev/<vg>/<lv>       # filesystem type, if any
mount -o ro /dev/<vg>/<lv> <mountpoint>
```

Activated volume groups hold kernel device state, so they must be deactivated
(`vgchange -an <vg_name>`) before the underlying loop or NBD device is detached,
otherwise the device stays busy and cleanup fails. This is the main new cleanup
requirement beyond what the existing loop/NBD unmount path already does.

### 3. Prior art

- **The Sleuth Kit / Autopsy** expose LVM volumes through `mmls`/`mmstat` and pool
  metadata parsing, without activating anything; they read the LVM layout directly.
  That approach avoids kernel state but means reimplementing the on-disk format,
  which is more work than shelling out to the `lvm2` tools.
- **Dissect** (`dissect.target`) parses LVM2 metadata in Python and reconstructs
  logical volumes without the kernel. It is the more robust long-term answer, but
  OpenRelik's `BlockDevice` is built around kernel loop/NBD mapping, so activating
  the VG with `vgchange` is the natural fit.
- **dfVFS (Plaso)** mounts via the kernel where possible and handles LVM through
  its volume system abstraction; analysts expect LVM volumes to appear alongside
  ordinary partitions in the mounted file list.

Shelling out to `pvs`/`lvs`/`vgchange` was chosen because it reuses the standard
LVM tooling and fits the existing `subprocess`-based design. The trade-off is a
dependency on the `lvm2` package and kernel device state that has to be cleaned up.

### 4. Evidence integrity and cleanup

The existing `BlockDevice` already maps images read-only (`losetup --read-only`,
`qemu-nbd --read-only`) and mounts with `-o ro` (plus `noload`/`norecovery` for
ext/xfs). LVM activation with `vgchange -ay` does not write to the image in normal
use, but the activated VG holds kernel state, so it must be undone in `umount()`.
Unformatted logical volumes are expected in real images (e.g. a VG that reserves an
LV for swap or thin-pool data), so they must be skipped rather than treated as an
error. A device that `blkid` reports as having no filesystem must stay distinct
from a device that does not exist, so genuine `blkid` failures still surface.

## Ideas it gave me

- Add an `_is_lvm2_member()` helper and LVM helpers that mirror the existing
  `subprocess` helpers, tracking activated VGs on the instance for cleanup.
- Route LVM detection through `_parse_partitions()` for both the whole-disk and
  per-partition cases, keeping the existing `min_partition_size` gate so tiny
  partitions are not probed for LVM.
- Raise a `NoFilesystemError` only when `blkid` returns 2 and the device exists,
  and skip LVs that raise it, so unformatted LVs are not a failure.
- Deactivate VGs in `umount()` before detaching the block device, and extend
  `setup()`'s failure path to unwind partial activation.

## Sources

- Issue: https://github.com/openrelik/openrelik/issues/40
- `libs/worker-common/openrelik_worker_common/mount_utils.py`: current `BlockDevice`
  implementation (`setup`, `_parse_partitions`, `_get_fstype`, `umount`).
- LVM2 man pages: `pvs(8)`, `lvs(8)`, `vgchange(8)`.
- Dissect target LVM2 support: https://github.com/fox-it/dissect.target
- The Sleuth Kit volume system: https://github.com/sleuthkit/sleuthkit
