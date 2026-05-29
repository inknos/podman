package vmbootpatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"unicode/utf16"

	"github.com/sirupsen/logrus"
	"go.podman.io/common/pkg/config"
	"go.podman.io/podman/v6/pkg/machine/define"
)

const (
	gptHeaderSignature = "EFI PART"
	gptPartEntrySize   = 128
	sectorSize         = 512
)

// gptHeader represents the GPT header at LBA 1.
type gptHeader struct {
	Signature          [8]byte
	Revision           uint32
	HeaderSize         uint32
	HeaderCRC32        uint32
	Reserved           uint32
	MyLBA              uint64
	AlternateLBA       uint64
	FirstUsableLBA     uint64
	LastUsableLBA      uint64
	DiskGUID           [16]byte
	PartitionEntryLBA  uint64
	NumPartEntries     uint32
	PartEntrySize      uint32
	PartEntryCRC32     uint32
}

// gptPartEntry represents a single GPT partition entry.
type gptPartEntry struct {
	TypeGUID   [16]byte
	UniqueGUID [16]byte
	FirstLBA   uint64
	LastLBA    uint64
	Attributes uint64
	Name       [72]byte // UTF-16LE, 36 code units
}

func (e *gptPartEntry) isEmpty() bool {
	var zero [16]byte
	return e.TypeGUID == zero
}

func (e *gptPartEntry) nameString() string {
	u16 := make([]uint16, 36)
	for i := 0; i < 36; i++ {
		u16[i] = binary.LittleEndian.Uint16(e.Name[i*2 : i*2+2])
	}
	// Trim null terminators
	n := 0
	for n < len(u16) && u16[n] != 0 {
		n++
	}
	return string(utf16.Decode(u16[:n]))
}

// bootPartition holds the location of the boot partition within the raw image.
type bootPartition struct {
	StartByte uint64
	SizeBytes uint64
}

// findBootPartition reads the GPT from a raw disk image and returns the
// byte offset and size of the partition named "boot".
func findBootPartition(rawPath string) (*bootPartition, error) {
	f, err := os.Open(rawPath)
	if err != nil {
		return nil, fmt.Errorf("opening raw image: %w", err)
	}
	defer f.Close()

	// Read GPT header at LBA 1
	if _, err := f.Seek(int64(sectorSize), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seeking to GPT header: %w", err)
	}
	var hdr gptHeader
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("reading GPT header: %w", err)
	}
	if string(hdr.Signature[:]) != gptHeaderSignature {
		return nil, errors.New("not a valid GPT disk (bad signature)")
	}

	if _, err := f.Seek(int64(hdr.PartitionEntryLBA)*sectorSize, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seeking to partition entries: %w", err)
	}

	for i := uint32(0); i < hdr.NumPartEntries; i++ {
		var entry gptPartEntry
		if err := binary.Read(f, binary.LittleEndian, &entry); err != nil {
			return nil, fmt.Errorf("reading partition entry %d: %w", i, err)
		}
		// Skip trailing padding if entry size > our struct
		if hdr.PartEntrySize > gptPartEntrySize {
			if _, err := f.Seek(int64(hdr.PartEntrySize-gptPartEntrySize), io.SeekCurrent); err != nil {
				return nil, fmt.Errorf("skipping partition entry padding: %w", err)
			}
		}
		if entry.isEmpty() {
			continue
		}
		if entry.nameString() == "boot" {
			return &bootPartition{
				StartByte: entry.FirstLBA * sectorSize,
				SizeBytes: (entry.LastLBA - entry.FirstLBA + 1) * sectorSize,
			}, nil
		}
	}
	return nil, errors.New("no partition named \"boot\" found in GPT")
}

func findHelperBinary(name string) (string, error) {
	cfg, err := config.Default()
	if err != nil {
		return "", err
	}
	return cfg.FindHelperBinary(name, true)
}

// convertImage runs qemu-img convert between formats.
func convertImage(src, dst, outputFormat string) error {
	qemuImg, err := findHelperBinary("qemu-img")
	if err != nil {
		return fmt.Errorf("finding qemu-img: %w", err)
	}
	cmd := exec.Command(qemuImg, "convert", "-O", outputFormat, src, dst)
	cmd.Stderr = &bytes.Buffer{}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("qemu-img convert to %s: %w: %s", outputFormat, err, cmd.Stderr)
	}
	return nil
}

// extractPartition copies a partition from the raw image to a separate file.
func extractPartition(rawPath string, part *bootPartition, outPath string) error {
	src, err := os.Open(rawPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := src.Seek(int64(part.StartByte), io.SeekStart); err != nil {
		return err
	}
	_, err = io.CopyN(dst, src, int64(part.SizeBytes))
	return err
}

// patchPartition writes a modified partition image back into the raw image.
func patchPartition(rawPath string, part *bootPartition, partPath string) error {
	src, err := os.Open(partPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(rawPath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := dst.Seek(int64(part.StartByte), io.SeekStart); err != nil {
		return err
	}
	_, err = io.CopyN(dst, src, int64(part.SizeBytes))
	return err
}

// writeFileWithDebugfs writes content to a path inside an ext4 filesystem image
// using debugfs from e2fsprogs.
func writeFileWithDebugfs(partitionImg, fsPath string, content []byte) error {
	debugfs, err := findHelperBinary("debugfs")
	if err != nil {
		return fmt.Errorf("finding debugfs: %w", err)
	}

	dir := filepath.Dir(partitionImg)
	tmpFile, err := os.CreateTemp(dir, "bootcfg-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	// Ensure parent directory exists in the ext4 image
	fsDir := filepath.Dir(fsPath)
	if fsDir != "." && fsDir != "/" {
		mkdirCmd := exec.Command(debugfs, "-w", "-R", fmt.Sprintf("mkdir %s", fsDir), partitionImg)
		// mkdir may fail if the directory already exists; that's fine
		_ = mkdirCmd.Run()
	}

	cmd := exec.Command(debugfs, "-w", "-R",
		fmt.Sprintf("write %s %s", tmpFile.Name(), fsPath),
		partitionImg,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("debugfs write: %w: %s", err, stderr.String())
	}
	if debugfsHasError(stderr.Bytes()) {
		return fmt.Errorf("debugfs write failed: %s", stderr.String())
	}
	return nil
}

// removeFileWithDebugfs removes a file from an ext4 filesystem image using debugfs.
// debugfs always exits 0, so we check stderr for error messages.
func removeFileWithDebugfs(partitionImg, fsPath string) error {
	debugfs, err := findHelperBinary("debugfs")
	if err != nil {
		return fmt.Errorf("finding debugfs: %w", err)
	}

	cmd := exec.Command(debugfs, "-w", "-R",
		fmt.Sprintf("rm %s", fsPath),
		partitionImg,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("debugfs rm: %w: %s", err, stderr.String())
	}
	if debugfsHasError(stderr.Bytes()) {
		return fmt.Errorf("debugfs rm failed: %s", stderr.String())
	}
	return nil
}

// bootFileExists checks whether a file exists inside an ext4 filesystem image
// using debugfs stat. Returns false if the file does not exist, the image is
// not a valid ext4 filesystem, or debugfs is not available.
func bootFileExists(partitionImg, fsPath string) bool {
	debugfs, err := findHelperBinary("debugfs")
	if err != nil {
		return false
	}

	cmd := exec.Command(debugfs, "-R",
		fmt.Sprintf("stat %s", fsPath),
		partitionImg,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return false
	}
	return !debugfsHasError(stderr.Bytes())
}

// debugfsHasError returns true if debugfs stderr output indicates a failure.
// debugfs always exits 0, reporting errors only via stderr text.
func debugfsHasError(stderr []byte) bool {
	return bytes.Contains(stderr, []byte("not found")) ||
		bytes.Contains(stderr, []byte("File not found")) ||
		bytes.Contains(stderr, []byte("Bad magic")) ||
		bytes.Contains(stderr, []byte("Filesystem not open"))
}

// imageFormatForPath returns the qemu-img format name for the given VMType.
func imageFormatForPath(vmType define.VMType) string {
	switch vmType.ImageFormat() {
	case define.Raw:
		return "raw"
	case define.Vhdx:
		return "vhdx"
	default:
		return "qcow2"
	}
}

// isRawFormat returns true if the VMType uses raw disk images that can
// be patched in place without conversion.
func isRawFormat(vmType define.VMType) bool {
	return vmType.ImageFormat() == define.Raw
}

// WriteBootFile writes content to a file path within the /boot ext4 partition
// of a VM disk image. The fsPath is relative to the boot partition root
// (e.g. "grub2/user.cfg").
//
// For raw images (AppleHV, LibKrun), the image is patched in place.
// For qcow2/vhdx images, a temporary raw conversion is performed.
func WriteBootFile(imagePath string, vmType define.VMType, fsPath string, content []byte) error {
	if vmType == define.WSLVirt {
		return errors.New("WriteBootFile is not supported for WSL (no disk image)")
	}

	logrus.Debugf("Patching boot partition: writing %q (%d bytes) in %s", fsPath, len(content), imagePath)

	tmpDir, err := os.MkdirTemp("", "podman-bootpatch-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rawPath := imagePath
	needsConvert := !isRawFormat(vmType)

	if needsConvert {
		rawPath = filepath.Join(tmpDir, "disk.raw")
		logrus.Debugf("Converting %s to raw: %s", imageFormatForPath(vmType), rawPath)
		if err := convertImage(imagePath, rawPath, "raw"); err != nil {
			return err
		}
	}

	part, err := findBootPartition(rawPath)
	if err != nil {
		return fmt.Errorf("finding boot partition: %w", err)
	}
	logrus.Debugf("Boot partition: offset=%d size=%d", part.StartByte, part.SizeBytes)

	partPath := filepath.Join(tmpDir, "boot.raw")
	if err := extractPartition(rawPath, part, partPath); err != nil {
		return fmt.Errorf("extracting boot partition: %w", err)
	}

	if err := writeFileWithDebugfs(partPath, fsPath, content); err != nil {
		return fmt.Errorf("writing file via debugfs: %w", err)
	}

	if err := patchPartition(rawPath, part, partPath); err != nil {
		return fmt.Errorf("patching boot partition back: %w", err)
	}

	if needsConvert {
		outFmt := imageFormatForPath(vmType)
		logrus.Debugf("Converting raw back to %s: %s", outFmt, imagePath)
		if err := convertImage(rawPath, imagePath, outFmt); err != nil {
			return err
		}
	}

	logrus.Debugf("Successfully wrote %q to boot partition of %s", fsPath, imagePath)
	return nil
}

// RemoveBootFile removes a file from the /boot ext4 partition of a VM disk
// image. The fsPath is relative to the boot partition root (e.g. "grub2/user.cfg").
// If the file does not exist, this is a no-op (returns nil).
func RemoveBootFile(imagePath string, vmType define.VMType, fsPath string) error {
	if vmType == define.WSLVirt {
		return errors.New("RemoveBootFile is not supported for WSL (no disk image)")
	}

	logrus.Debugf("Removing %q from boot partition of %s", fsPath, imagePath)

	tmpDir, err := os.MkdirTemp("", "podman-bootpatch-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	rawPath := imagePath
	needsConvert := !isRawFormat(vmType)

	if needsConvert {
		rawPath = filepath.Join(tmpDir, "disk.raw")
		logrus.Debugf("Converting %s to raw: %s", imageFormatForPath(vmType), rawPath)
		if err := convertImage(imagePath, rawPath, "raw"); err != nil {
			return err
		}
	}

	part, err := findBootPartition(rawPath)
	if err != nil {
		return fmt.Errorf("finding boot partition: %w", err)
	}

	partPath := filepath.Join(tmpDir, "boot.raw")
	if err := extractPartition(rawPath, part, partPath); err != nil {
		return fmt.Errorf("extracting boot partition: %w", err)
	}

	if !bootFileExists(partPath, fsPath) {
		logrus.Debugf("File %q not present in boot partition, nothing to remove", fsPath)
		return nil
	}

	if err := removeFileWithDebugfs(partPath, fsPath); err != nil {
		return fmt.Errorf("removing file via debugfs: %w", err)
	}

	if err := patchPartition(rawPath, part, partPath); err != nil {
		return fmt.Errorf("patching boot partition back: %w", err)
	}

	if needsConvert {
		outFmt := imageFormatForPath(vmType)
		logrus.Debugf("Converting raw back to %s: %s", outFmt, imagePath)
		if err := convertImage(rawPath, imagePath, outFmt); err != nil {
			return err
		}
	}

	logrus.Debugf("Successfully removed %q from boot partition of %s", fsPath, imagePath)
	return nil
}

const grubTimeoutMarker = ".grub-debug-timeout"

func markerPath(imagePath string) string {
	return imagePath + "." + grubTimeoutMarker
}

// SetGRUBTimeout writes a user.cfg to the boot partition that sets the
// GRUB menu timeout to the given number of seconds. It also creates a
// sidecar marker file next to the disk image so ClearGRUBTimeout can
// detect whether cleanup is needed without touching the disk image.
func SetGRUBTimeout(imagePath string, vmType define.VMType, seconds int) error {
	content := fmt.Sprintf("set timeout=%d\n", seconds)
	if err := WriteBootFile(imagePath, vmType, "grub2/user.cfg", []byte(content)); err != nil {
		return err
	}
	// Best-effort marker; if it fails, ClearGRUBTimeout will just do
	// the expensive check next time.
	if err := os.WriteFile(markerPath(imagePath), []byte("1"), 0644); err != nil {
		logrus.Debugf("Failed to write GRUB timeout marker: %v", err)
	}
	return nil
}

// ClearGRUBTimeout removes user.cfg from the boot partition, restoring
// the default GRUB timeout behavior. If no previous SetGRUBTimeout was
// called (no sidecar marker file), this is a true no-op with zero disk I/O.
func ClearGRUBTimeout(imagePath string, vmType define.VMType) error {
	mp := markerPath(imagePath)
	if _, err := os.Stat(mp); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := RemoveBootFile(imagePath, vmType, "grub2/user.cfg"); err != nil {
		return err
	}
	os.Remove(mp)
	return nil
}
