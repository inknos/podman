package vmbootpatch

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/podman/v6/pkg/machine/define"
)

// writeUTF16Name encodes a Go string into the 72-byte GPT partition name field.
func writeUTF16Name(name string) [72]byte {
	var buf [72]byte
	runes := []rune(name)
	encoded := utf16.Encode(runes)
	for i, u := range encoded {
		if i >= 36 {
			break
		}
		binary.LittleEndian.PutUint16(buf[i*2:], u)
	}
	return buf
}

// createTestGPTImage builds a minimal raw disk image with a GPT containing
// the FCOS-like partition layout: BIOS-BOOT, EFI-SYSTEM, boot, root.
func createTestGPTImage(t *testing.T, dir string) string {
	t.Helper()

	const (
		diskSectors = 131072 // 64 MiB
		ss          = 512
		numParts    = 4
	)

	imgPath := filepath.Join(dir, "test.raw")
	f, err := os.Create(imgPath)
	require.NoError(t, err)

	// Size the file
	require.NoError(t, f.Truncate(diskSectors*ss))

	// Partition entries (128 bytes each)
	biosBootType := [16]byte{0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E, 0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49}
	efiType := [16]byte{0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}
	linuxType := [16]byte{0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4}

	// Partition layout:
	// 1: BIOS-BOOT  sectors 2048..4095  (1 MiB)
	// 2: EFI-SYSTEM sectors 4096..8191  (2 MiB)
	// 3: boot       sectors 8192..16383 (4 MiB, our target)
	// 4: root       sectors 16384..131037
	entries := []gptPartEntry{
		{TypeGUID: biosBootType, FirstLBA: 2048, LastLBA: 4095, Name: writeUTF16Name("BIOS-BOOT")},
		{TypeGUID: efiType, FirstLBA: 4096, LastLBA: 8191, Name: writeUTF16Name("EFI-SYSTEM")},
		{TypeGUID: linuxType, FirstLBA: 8192, LastLBA: 16383, Name: writeUTF16Name("boot")},
		{TypeGUID: linuxType, FirstLBA: 16384, LastLBA: 131037, Name: writeUTF16Name("root")},
	}

	// Write partition entries at LBA 2
	entryBuf := make([]byte, numParts*gptPartEntrySize)
	for i, e := range entries {
		off := i * gptPartEntrySize
		copy(entryBuf[off:], e.TypeGUID[:])
		copy(entryBuf[off+16:], e.UniqueGUID[:])
		binary.LittleEndian.PutUint64(entryBuf[off+32:], e.FirstLBA)
		binary.LittleEndian.PutUint64(entryBuf[off+40:], e.LastLBA)
		binary.LittleEndian.PutUint64(entryBuf[off+48:], e.Attributes)
		copy(entryBuf[off+56:], e.Name[:])
	}
	_, err = f.WriteAt(entryBuf, 2*ss)
	require.NoError(t, err)

	// Build GPT header at LBA 1
	hdr := gptHeader{
		Revision:          0x00010000,
		HeaderSize:        92,
		MyLBA:             1,
		AlternateLBA:      uint64(diskSectors - 1),
		FirstUsableLBA:    34,
		LastUsableLBA:     uint64(diskSectors - 34),
		PartitionEntryLBA: 2,
		NumPartEntries:    uint32(numParts),
		PartEntrySize:     gptPartEntrySize,
		PartEntryCRC32:    crc32.ChecksumIEEE(entryBuf),
	}
	copy(hdr.Signature[:], gptHeaderSignature)

	// Serialize header without CRC, then compute CRC
	hdrBuf := make([]byte, 92)
	copy(hdrBuf[0:8], hdr.Signature[:])
	binary.LittleEndian.PutUint32(hdrBuf[8:], hdr.Revision)
	binary.LittleEndian.PutUint32(hdrBuf[12:], hdr.HeaderSize)
	// hdrBuf[16:20] = HeaderCRC32 = 0 for computation
	binary.LittleEndian.PutUint32(hdrBuf[20:], hdr.Reserved)
	binary.LittleEndian.PutUint64(hdrBuf[24:], hdr.MyLBA)
	binary.LittleEndian.PutUint64(hdrBuf[32:], hdr.AlternateLBA)
	binary.LittleEndian.PutUint64(hdrBuf[40:], hdr.FirstUsableLBA)
	binary.LittleEndian.PutUint64(hdrBuf[48:], hdr.LastUsableLBA)
	copy(hdrBuf[56:72], hdr.DiskGUID[:])
	binary.LittleEndian.PutUint64(hdrBuf[72:], hdr.PartitionEntryLBA)
	binary.LittleEndian.PutUint32(hdrBuf[80:], hdr.NumPartEntries)
	binary.LittleEndian.PutUint32(hdrBuf[84:], hdr.PartEntrySize)
	binary.LittleEndian.PutUint32(hdrBuf[88:], hdr.PartEntryCRC32)

	hdrCRC := crc32.ChecksumIEEE(hdrBuf)
	binary.LittleEndian.PutUint32(hdrBuf[16:], hdrCRC)

	_, err = f.WriteAt(hdrBuf, 1*ss)
	require.NoError(t, err)

	require.NoError(t, f.Close())
	return imgPath
}

func TestFindBootPartition(t *testing.T) {
	dir := t.TempDir()
	imgPath := createTestGPTImage(t, dir)

	part, err := findBootPartition(imgPath)
	require.NoError(t, err)
	require.NotNil(t, part)

	// boot partition: firstLBA=8192, lastLBA=16383
	assert.Equal(t, uint64(8192*512), part.StartByte)
	assert.Equal(t, uint64((16383-8192+1)*512), part.SizeBytes)
}

func TestFindBootPartitionNoBootPart(t *testing.T) {
	dir := t.TempDir()

	// Create a minimal GPT with no "boot" partition
	const diskSectors = 8192
	imgPath := filepath.Join(dir, "noboot.raw")
	f, err := os.Create(imgPath)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(diskSectors*512))

	linuxType := [16]byte{0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4}
	entry := gptPartEntry{TypeGUID: linuxType, FirstLBA: 2048, LastLBA: 4095, Name: writeUTF16Name("root")}

	entryBuf := make([]byte, gptPartEntrySize)
	copy(entryBuf[0:], entry.TypeGUID[:])
	binary.LittleEndian.PutUint64(entryBuf[32:], entry.FirstLBA)
	binary.LittleEndian.PutUint64(entryBuf[40:], entry.LastLBA)
	copy(entryBuf[56:], entry.Name[:])
	_, err = f.WriteAt(entryBuf, 2*512)
	require.NoError(t, err)

	hdrBuf := make([]byte, 92)
	copy(hdrBuf[0:8], gptHeaderSignature)
	binary.LittleEndian.PutUint32(hdrBuf[8:], 0x00010000)
	binary.LittleEndian.PutUint32(hdrBuf[12:], 92)
	binary.LittleEndian.PutUint64(hdrBuf[24:], 1)
	binary.LittleEndian.PutUint64(hdrBuf[72:], 2)
	binary.LittleEndian.PutUint32(hdrBuf[80:], 1)
	binary.LittleEndian.PutUint32(hdrBuf[84:], gptPartEntrySize)
	binary.LittleEndian.PutUint32(hdrBuf[88:], crc32.ChecksumIEEE(entryBuf))
	hdrCRC := crc32.ChecksumIEEE(hdrBuf)
	binary.LittleEndian.PutUint32(hdrBuf[16:], hdrCRC)
	_, err = f.WriteAt(hdrBuf, 512)
	require.NoError(t, err)

	require.NoError(t, f.Close())

	_, err = findBootPartition(imgPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no partition named")
}

func TestFindBootPartitionBadSignature(t *testing.T) {
	dir := t.TempDir()
	imgPath := filepath.Join(dir, "bad.raw")
	f, err := os.Create(imgPath)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(4096))
	require.NoError(t, f.Close())

	_, err = findBootPartition(imgPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad signature")
}

func TestExtractAndPatchPartition(t *testing.T) {
	dir := t.TempDir()
	imgPath := createTestGPTImage(t, dir)

	part, err := findBootPartition(imgPath)
	require.NoError(t, err)

	// Write known data into the boot partition area
	f, err := os.OpenFile(imgPath, os.O_WRONLY, 0)
	require.NoError(t, err)
	marker := []byte("BOOTDATA")
	_, err = f.WriteAt(marker, int64(part.StartByte))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Extract
	partPath := filepath.Join(dir, "boot.raw")
	require.NoError(t, extractPartition(imgPath, part, partPath))

	// Verify extracted data starts with our marker
	data, err := os.ReadFile(partPath)
	require.NoError(t, err)
	assert.Equal(t, int(part.SizeBytes), len(data))
	assert.Equal(t, marker, data[:len(marker)])

	// Modify extracted partition
	newMarker := []byte("MODIFIED")
	copy(data, newMarker)
	require.NoError(t, os.WriteFile(partPath, data, 0644))

	// Patch back
	require.NoError(t, patchPartition(imgPath, part, partPath))

	// Verify the modification in the disk image
	f2, err := os.Open(imgPath)
	require.NoError(t, err)
	buf := make([]byte, len(newMarker))
	_, err = f2.ReadAt(buf, int64(part.StartByte))
	require.NoError(t, err)
	require.NoError(t, f2.Close())
	assert.Equal(t, newMarker, buf)
}

func TestBootFileExistsOnNonExt4(t *testing.T) {
	dir := t.TempDir()
	imgPath := createTestGPTImage(t, dir)

	part, err := findBootPartition(imgPath)
	require.NoError(t, err)

	partPath := filepath.Join(dir, "boot.raw")
	require.NoError(t, extractPartition(imgPath, part, partPath))

	// The partition is zeroed out (not a real ext4), so bootFileExists
	// should return false gracefully rather than crashing.
	assert.False(t, bootFileExists(partPath, "grub2/user.cfg"))
}

func TestRemoveFileWithDebugfsOnNonExt4(t *testing.T) {
	dir := t.TempDir()
	imgPath := createTestGPTImage(t, dir)

	part, err := findBootPartition(imgPath)
	require.NoError(t, err)

	partPath := filepath.Join(dir, "boot.raw")
	require.NoError(t, extractPartition(imgPath, part, partPath))

	// Removing from a non-ext4 image should return an error (not panic).
	err = removeFileWithDebugfs(partPath, "grub2/user.cfg")
	assert.Error(t, err)
}

func TestClearGRUBTimeoutNoopWithoutMarker(t *testing.T) {
	dir := t.TempDir()
	fakeDisk := filepath.Join(dir, "disk.qcow2")

	// Create a tiny file that is NOT a valid disk image
	require.NoError(t, os.WriteFile(fakeDisk, []byte("not a disk"), 0644))

	// No marker file exists, so ClearGRUBTimeout should be a pure no-op:
	// it must not attempt to convert/parse/extract the disk image at all.
	// If it did, it would fail because the file is not a valid qcow2.
	err := ClearGRUBTimeout(fakeDisk, define.QemuVirt)
	assert.NoError(t, err)
}

func TestClearGRUBTimeoutMarkerLifecycle(t *testing.T) {
	dir := t.TempDir()
	fakeDisk := filepath.Join(dir, "disk.raw")
	require.NoError(t, os.WriteFile(fakeDisk, []byte("not a disk"), 0644))

	mp := markerPath(fakeDisk)

	// No marker -> ClearGRUBTimeout is a no-op
	require.NoError(t, ClearGRUBTimeout(fakeDisk, define.QemuVirt))
	_, err := os.Stat(mp)
	assert.True(t, os.IsNotExist(err))

	// Create marker manually (simulating what SetGRUBTimeout does)
	require.NoError(t, os.WriteFile(mp, []byte("1"), 0644))

	// With marker present, ClearGRUBTimeout will attempt to actually
	// process the disk image and fail (since it's not a real image).
	// This proves it only does work when the marker is present.
	err = ClearGRUBTimeout(fakeDisk, define.QemuVirt)
	assert.Error(t, err)

	// Marker should still be there since the removal failed
	_, err = os.Stat(mp)
	assert.NoError(t, err)
}

func TestGptPartEntryNameString(t *testing.T) {
	e := gptPartEntry{Name: writeUTF16Name("boot")}
	assert.Equal(t, "boot", e.nameString())

	e2 := gptPartEntry{Name: writeUTF16Name("EFI-SYSTEM")}
	assert.Equal(t, "EFI-SYSTEM", e2.nameString())

	e3 := gptPartEntry{}
	assert.Equal(t, "", e3.nameString())
	assert.True(t, e3.isEmpty())
}
