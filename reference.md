# Reference: formats, offsets and pitfalls

Values below were measured on a UE 4.27 title (IoStore TOC version 3).
Verify every offset against your own files — vendors customize the layout.

## .utoc header (FIoStoreTocHeader, 144 bytes)

| Offset | Field |
|---|---|
| 0 | magic `-==--==--==--==-` (16 bytes) |
| 16 | version (u8): 2 = DirectoryIndex (4.26), 3 = PartitionSize (4.27 / 5.0) |
| 0x38 | ContainerId (u64) — use these as memory-scan anchors |
| 0x50 | ContainerFlags (u8): 0x0b = Compressed(1) \| Encrypted(2) \| Indexed(8) |
| EncryptionKeyGuid | all-zero ⇒ global default key shared by all zero-guid containers |

## TOC body layout (version 3), after the header

Order: ChunkIds → ChunkOffsetLengths → (PerfectHash if present; none in v3) →
CompressionBlocks → CompressionMethodNames (32 bytes each, index 0 = implicit
"None") → (Signature block if Signed flag) → **DirectoryIndex** → ChunkMetas.

- Only the **DirectoryIndex** is AES-256-ECB encrypted in stock UE (16-byte
  aligned). It decrypts to an `FIoDirectoryIndexResource`.
- **Don't compute the directory-index offset by summing section sizes** — padding
  drifts (we were off by 10 bytes repeatedly). Instead **search for the `Oodle`
  compression-method-name bytes**, then directory index starts right after the
  method-names block (`method_start + count*32`, padded). Confirm the region length
  is a clean multiple of 16 and entropy is ~7.9.

## FIoDirectoryIndexResource (decrypted)

- FString mount point: int32 length then bytes. **Length can be 1 (empty string,
  just a null)** — do not assume it contains `../../../`.
- Directory entries: `Name, FirstChildEntry, NextSiblingEntry, FirstFileEntry`
  (u32 each; `0xFFFFFFFF` = none).
- File entries: `Name, NextFileEntry, UserData` (UserData → TOC chunk index).
- Validation = these tables parse sanely (monotonic children, valid sentinels).

## ChunkOffsetLength entries

5-byte offset + 5-byte length, **40-bit big-endian** each (10 bytes/entry).

## Oodle decompression

`.ucas` compression blocks are usually Oodle Kraken. Get `oo2core_9_win64.dll`
(x64). GitHub repo `WorkingRobot/OodleUE` mirrors it; if GitHub is blocked, the
**jsDelivr CDN** (`cdn.jsdelivr.net/gh/...`) and `raw.githubusercontent.com` worked
from mainland China. Verify it's a valid x64 PE exporting `OodleLZ_Decompress`.
Call via ctypes (`iostore_extract.py` has the exact signature).

## .pak (legacy, v11) alongside IoStore

Magic `0x5A6F12E1` at footer. IoStore games ship tiny **placeholder** paks (often 0
entries) — real data is in `.ucas`. The pak index uses standard UE encryption with
the **same** key (encrypted-index flag + zero guid). FModel handles these fine.

## Vendor customization checklist (reference build)

These are why stock FModel/CUE4Parse fail — probe for each:

1. **OffsetAndLength table extra-encrypted**: the ChunkOffsetLengths region is
   AES-encrypted and padded to a 16-byte multiple. Detect by: offsets look like
   garbage / out of bounds when read raw, but the region size is 16-aligned;
   decrypt it and offsets become monotonic 64 KB-aligned. Note a container whose
   plain table size is *already* 16-aligned defeats "has padding?" detection — fall
   back to plausibility (try-parse, decrypt on out-of-bounds).
2. **Blocks plaintext despite Encrypted flag**: test-decompress block 0 raw; if
   Oodle succeeds without decrypting, clear the Encrypted flag when normalizing so
   readers don't "decrypt" plaintext.
3. **Mount point empty + `../../../` as literal `..` dirs**: FModel shows only
   `NonePackageChunk` and can't map to `/Game`. Rewrite the index: set mount point
   `../../../`, splice real dirs under the deepest `..`, drop `NonePackageChunk`.

`tools/normalize_utoc.py` rewrites all of the above into stock UE4.27 TOCs; verify
by extracting one asset from the normalized copy and diffing byte-for-byte against a
direct extraction.

## Customized mesh format (why FModel couldn't draw the body)

Even after normalizing the container, the Static/SkeletalMesh render data was
customized, so a **direct parser** was needed:

- **Zen package**: parse by the **export bundle serialization order**, not the
  export map's `CookedSerialOffset` (that pointed at a Socket, not the mesh).
- **Vertex positions quantized**: 8 bytes/vertex = four 16-bit components, 4th
  constant `0x7fff`. A 7-float header precedes it (bbox center xyz, half-size xyz,
  radius). Decode: `pos = center + halfsize * q/32767`.
- UVs: 3 sets as half-floats. Normals/tangents: packed int8. Normal maps need Z
  reconstruct + G-channel flip (DirectX→OpenGL); ARM textures already match glTF.
- Mesh sections carry an extra `bVisibleInRayTracing` field (UE4.27) that shifts
  everything — the drift that mislocated FModel's reader.
- Import table stores **CityHash64** of object paths with the top 2 bits as a type
  tag (`10` = package import); mask them off before matching to resolve which
  material instance each section uses.
- Textures: `PF_ASTC_4x4` mobile format, ~9 mips, big mips in `.ubulk`, small
  inline. Decode with `texture2ddecoder` (pure Python) → PNG.

## Coordinate conversion (UE → glTF/FBX/Unity)

UE is cm, left-handed, Z-up. glTF/Blender is m, right-handed, Y-up. Convert
positions and check triangle winding from normals. Export glTF/GLB, convert to FBX
headlessly in Blender.

## Reusable scripts (from the reference project `tools/`)

| Script | Purpose |
|---|---|
| `find-ue4-aes-key-arm64-v8a/…py` | IDA: static key scan (avenue B) |
| `scan_key.py` → `scripts/scan_mem_key.py` | live `/proc/mem` key scan (avenue D) |
| `verify_key.py` | confirm key + engine version |
| `build_paks_all.py` | merge APK-OBB + emulator containers (hardlinks) |
| `normalize_utoc.py` | rewrite customized TOCs to stock for FModel |
| `iostore_extract.py` | decrypt + Oodle-decompress `.ucas` chunks |
| `pak_reader.py` | legacy v11 pak reader |
| `skelmesh.py` / `texture.py` / `export_car.py` | direct mesh/texture export |
| `blender_convert.py` | glTF→FBX + headless render |
