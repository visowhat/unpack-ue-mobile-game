---
name: unpack-ue-mobile-game
description: Unpack Unreal Engine mobile games (IoStore .utoc/.ucas/.pak, including vendor-customized layouts) and recover the AES decryption key. Covers locating containers in APK/OBB and emulator data, the ordered avenues for obtaining the runtime AES key (published keys, IDA signature scan of libUE4.so, Frida hook, and live /proc/pid/mem scan anchored on ContainerIds), validating the key, and exporting meshes/textures. Use when extracting 3D models, textures, or assets from a UE Android game, when a .utoc/.ucas/.pak is AES-encrypted, or when the user asks how to find a UE pak/IoStore AES key.
disable-model-invocation: true
---

# Unpacking Unreal Engine mobile games

Workflow for pulling assets (meshes, textures) out of a UE4/UE5 Android game whose
IoStore containers are AES-encrypted. The hard part is almost always **getting the
AES key**; this skill front-loads that and lists every avenue in order of effort.

This was validated end-to-end on a UE 4.27 Android title running in an Android
emulator. Working scripts referenced below live in that project's `tools/` and
can be copied.

## Workflow checklist

```
- [ ] 1. Locate the containers (APK / OBB / emulator per-asset downloads)
- [ ] 2. Identify engine version + IoStore TOC version
- [ ] 3. Get the AES key (try avenues A→D in order; see below)
- [ ] 4. Validate the key against a real .utoc directory index
- [ ] 5. Merge all containers into one directory
- [ ] 6. Detect vendor customizations; normalize or write a custom reader
- [ ] 7. Export meshes/textures (FModel, or a custom parser if FModel chokes)
```

## 1. Locate the containers

UE mobile assets ship as IoStore triplets: `.utoc` (index), `.ucas` (data), and a
small placeholder `.pak`. Hunt in this order:

- **APK**: unzip it. The base game is often a large file **disguised as an image**
  (e.g. `assets/main.obb.png`) that is actually an uncompressed zip holding
  `global.*`, `b_*`, `d_*` (`.ucas`+`.utoc`). Open it as a zip, not an image.
- **OBB**: `/sdcard/Android/obb/<pkg>/` or inside the disguised file above.
- **Emulator / device app data** (needs root): `/data/data/<pkg>/files/.../Game`
  or `.../DownloadResource`. Games download cars/levels **on demand**, named like
  `12_<id>.ucas`. Trigger in-game downloads first, then pull. Re-pull later — the
  set grows as the player races/opens more content. Watch for `*_hdiff` binary
  patch files; exclude them so they don't shadow real same-named assets.

Copy everything local; don't operate on live emulator files.

## 2. Identify the engine version

- Grep `libUE4.so` for `++UE4+Release-4.` / `++UE5+Release-5.` (often stripped).
- If stripped, read the **IoStore TOC version** byte at offset 16 of a `.utoc`:
  `3` = PartitionSize ⇒ UE 4.27 / UE5.0; `2` = DirectoryIndex ⇒ 4.26.
- Compression is almost always **Oodle** (needs `oo2core_*.dll`, see reference).

## 3. Get the AES key — ordered avenues

The key is registered at runtime via the pak encryption-key delegate. For IoStore,
containers with an **all-zero `EncryptionKeyGuid` share one global key** — recover
one key and it opens every zero-guid container. Try in order:

**A. Published key.** Web-search `"<game>" AES key`, and check community tools
(FModel's key list, cark, UEViewer threads). Fastest if the title is known.

**B. Static IDA signature scan of `libUE4.so`** (no device needed). Load the
arm64-v8a `libUE4.so` in IDA and run `scripts/find-ue4-aes-key-arm64-v8a.py`
(GHFear / IllusorySoftware, bundled with this skill). It matches the ADRP/LDR signature of the key
delegate, follows it to the callback, and reads the 32-byte key the callback
references. Works only when the key is an embedded constant; fails if it is
assembled/decrypted at runtime (as it was in the reference game).

**C. Frida hook.** Attach and hook the AES key-schedule / delegate to capture the
key as it is registered. **Caveat that cost us a day:** x86 Android emulators
run arm64 `libUE4.so` through a binary translator
(**Houdini**). Native arm64 Frida gadget injection **crashes `libhoudini.so`**, and
the x64 Frida server only sees the x64 shell, not the translated arm instructions —
so you cannot hook `libUE4.so`. On a real arm64 device Frida is the easy path; in an
x86 emulator, skip to D.

**D. Live memory scan of `/proc/pid/mem`** (the approach that worked in the
emulator — only needs root ADB, no injection). The key sits in heap memory next to
each container's bookkeeping. Anchor on known **ContainerIds** instead of
brute-forcing:

1. Harvest every container's `ContainerId` (u64 at offset `0x38` of each `.utoc`).
2. Have the game open a car/level so the key is registered, then read
   `/proc/<pid>/mem` region by region (stream 64 MB slices via
   `adb exec-out dd if=/proc/<pid>/mem bs=4096 skip=.. count=..`; page-aligned,
   binary-safe; filter `rw-p` anon + `libUE4` regions from `/proc/<pid>/maps`).
3. Near each ContainerId hit, collect high-entropy 32-byte windows (≥24 distinct
   bytes). Rank by frequency — the one global key recurs once per mounted
   container, so it dominates (5104× vs the next in the reference run).
4. Validate top candidates (step 4). In the UE IoStore struct the key is commonly
   followed by `0b 00 00 00` (ContainerFlags = Compressed|Encrypted|Indexed), a
   handy confirmation.

Run with `scripts/scan_mem_key.py` (generalized copy of the project's
`scan_key.py`). Pass the pid, the ADB path/serial, a `.utoc`, and a ContainerId
list.

## 4. Validate the key

Never trust frequency alone — decrypt and check structure. The **directory index**
(an encrypted region inside the `.utoc`) AES-256-ECB-decrypts to an
`FIoDirectoryIndexResource`: a length-prefixed FString mount point followed by
directory/file entry tables with `0xFFFFFFFF` sentinels. A plausible decrypt = right
key. **Gotcha:** the mount point can be an empty string (length 1 = just a null),
so don't require `"../../../"` text — check for the structured entry tables instead.
See `reference.md` for locating the directory-index offset robustly (anchor on the
`Oodle` compression-method name rather than computing it).

## 5–7. Export

- Merge APK/OBB base containers + emulator downloads into one folder (hardlink the
  big `.ucas`/`.pak` to avoid copying gigabytes); point the exporter at it.
- **Try FModel first** (CUE4Parse-based; handles AES + Oodle, exports glTF/OBJ/PSK;
  fetches `oo2core` from GitHub, or drop the DLL in `Output/.data/` offline). Set a
  **custom/undetected game**, the engine version, and the key in its AES manager.
  FModel does **not** export FBX — go glTF then convert in Blender (headless
  `blender -b -P convert.py`).
- **Detect vendor customizations** — standard tools break on them. In the reference
  reference build: the TOC OffsetAndLength table was **extra AES-encrypted and padded
  to 16 bytes**; `.ucas` blocks were **plaintext despite the Encrypted flag**; the
  mount point was empty with `../../../` stored as three literal `..` directories;
  vertex positions were **16-bit quantized (8 bytes/vertex, not 12-byte float)** and
  mesh sections carried extra UE4.27 fields — which is exactly why FModel couldn't
  draw the body. Fixes: normalize each `.utoc` to stock layout for FModel
  (`tools/normalize_utoc.py`), or write a direct reader
  (`tools/iostore_extract.py` + `skelmesh.py` + `texture.py` + `export_car.py`) when
  the mesh format itself is customized.

Format details, byte offsets, Oodle setup, and the quantized-vertex/texture notes
are in [reference.md](reference.md).
