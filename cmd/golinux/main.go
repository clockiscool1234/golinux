// Command golinux is a non-interactive AMD64 Linux syscall emulator,
// ported from main.py.
//
// Usage:
//
//	golinux --vfs-root ./vfsroot /bin/hello
//	golinux --vfs-root ./vfsroot --host-file ./hello:/bin/hello /bin/hello arg1 arg2
//	golinux --vfs-root ./vfsroot -v /bin/hello
//	golinux -X alpine.tar.gz -r alpine /bin/sh
//
// Every flag has a short, single-dash acronym form and a long,
// double-dash descriptive form (either may be used interchangeably):
//
//	-r, --vfs-root         host directory backing the guest '/'
//	-v, --verbose          log every syscall to stderr
//	-n, --no-automount     skip the default proc/sysfs/devtmpfs mount at startup
//	-X, --extract-tarball  extract a tarball into the vfs root before running
//	-e, --env              extra environment variable KEY=VAL (repeatable)
//	-w, --cwd              initial guest working directory
//	-I, --host-file        import a host file into the VFS before running (repeatable)
//
// This pass supports the flags needed to run a simple statically-
// linked hello-world binary plus real filesystem/process-info
// programs. Networking and --native-perms are not wired up yet.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"golinux/internal/emulator"
	"golinux/internal/vfs"

	"github.com/klauspost/compress/gzip"
	"github.com/ulikunitz/xz"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// stringFlag registers a string flag under both a short acronym name
// (single dash, e.g. "-r") and a long descriptive name (double dash,
// e.g. "--vfs-root"), sharing the same backing variable.
func stringFlag(p *string, short, long, def, usage string) {
	flag.StringVar(p, short, def, usage)
	flag.StringVar(p, long, def, usage)
}

// boolFlag is stringFlag's counterpart for boolean flags.
func boolFlag(p *bool, short, long string, def bool, usage string) {
	flag.BoolVar(p, short, def, usage)
	flag.BoolVar(p, long, def, usage)
}

// listFlag is stringFlag's counterpart for repeatable flags.
func listFlag(p *stringList, short, long, usage string) {
	flag.Var(p, short, usage)
	flag.Var(p, long, usage)
}

// flagHelp describes one -x/--xyz pair for the hand-written usage
// text below (flag.PrintDefaults would list each registered name --
// short and long -- as a separate entry, which reads worse than a
// single combined line per flag).
type flagHelp struct {
	short, long, argHint, desc string
}

var flagHelps = []flagHelp{
	{"r", "vfs-root", "path", "host directory backing the guest '/'"},
	{"v", "verbose", "", "log every syscall to stderr"},
	{"n", "no-automount", "", "skip the default proc/sysfs/devtmpfs mount at startup; the guest can still mount(2) them itself"},
	{"X", "extract-tarball", "path", "extract a tarball (.tar, .tar.gz/.tgz, or .tar.xz) into the vfs root before running"},
	{"e", "env", "KEY=VAL", "extra environment variable for the guest. Repeatable."},
	{"w", "cwd", "path", "initial guest working directory (default \"/\")"},
	{"I", "host-file", "host:guest", "import a host file into the VFS before running, e.g. ./hello:/bin/hello. Repeatable."},
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: golinux [flags] <guest-program> [args...]")
	fmt.Fprintln(os.Stderr, "\nflags:")
	for _, h := range flagHelps {
		left := fmt.Sprintf("  -%s, --%s", h.short, h.long)
		if h.argHint != "" {
			left += " " + h.argHint
		}
		fmt.Fprintf(os.Stderr, "%-32s %s\n", left, h.desc)
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		vfsRoot     string
		verbose     bool
		cwd         string
		noAutoMnt   bool
		extractTar  string
		hostFiles   stringList
		envVars     stringList
	)
	stringFlag(&vfsRoot, "r", "vfs-root", "./vfsroot", "host directory backing the guest '/'")
	boolFlag(&verbose, "v", "verbose", false, "log every syscall to stderr")
	stringFlag(&cwd, "w", "cwd", "/", "initial guest working directory")
	boolFlag(&noAutoMnt, "n", "no-automount", false, "skip the default mount -t proc/sysfs/devtmpfs done at startup; the guest can still mount(2) them itself")
	stringFlag(&extractTar, "X", "extract-tarball", "", "extract a tarball into the vfs root before running, e.g. ./rootfs.tar.gz")
	listFlag(&hostFiles, "I", "host-file", "import a host file into the VFS before running, e.g. ./hello:/bin/hello. Repeatable.")
	listFlag(&envVars, "e", "env", "extra environment variable KEY=VAL. Repeatable.")
	flag.Usage = printUsage
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		return 2
	}
	program := args[0]
	progArgs := args[1:]

	vv, err := vfs.New(vfsRoot, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "golinux: opening vfs root: %v\n", err)
		return 1
	}

	if extractTar != "" {
		entries, err := os.ReadDir(vfsRoot)
		populated := false
		if err == nil {
			for _, e := range entries {
				if e.Name() != ".golinux_meta" {
					populated = true
					break
				}
			}
		}
		if populated {
			fmt.Fprintf(os.Stderr, "Warning: The VFS root (%s) is not empty.\n", vfsRoot)
			fmt.Fprintf(os.Stderr, "Extracting a new tarball will overwrite existing files.\n")
			fmt.Fprintf(os.Stderr, "Do you want to proceed? [y/N]: ")
			var resp string
			fmt.Scanln(&resp)
			resp = strings.ToLower(strings.TrimSpace(resp))
			if resp != "y" && resp != "yes" {
				fmt.Fprintln(os.Stderr, "Aborting.")
				return 1
			}
		}
		// -X/--extract-tarball always extracts into the vfs root ("/"),
		// e.g. `golinux -X alpine.tar.gz -r alpine /bin/sh` unpacks
		// alpine.tar.gz as the guest's whole filesystem before /bin/sh
		// is loaded from it.
		if err := extractRootfs(vv, extractTar, "/"); err != nil {
			fmt.Fprintf(os.Stderr, "golinux: extract tarball: %v\n", err)
			return 1
		}
	}

	if !noAutoMnt {
		if err := autoMount(vv); err != nil {
			fmt.Fprintf(os.Stderr, "golinux: auto-mount: %v\n", err)
			return 1
		}
	}

	for _, spec := range hostFiles {
		hostPath, guestPath, ok := splitHostSpec(spec)
		if !ok {
			fmt.Fprintf(os.Stderr, "golinux: --host-file expects HOST:GUEST, got %q\n", spec)
			return 2
		}
		if err := vv.ImportHostFile(hostPath, guestPath, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "golinux: importing %s -> %s: %v\n", hostPath, guestPath, err)
			return 1
		}
	}

	envp := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root", "TERM=xterm",
	}
	envp = append(envp, envVars...)

	argv := append([]string{program}, progArgs...)

	proc, err := emulator.NewProcess(vv, argv, envp, cwd, verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "golinux: creating process: %v\n", err)
		return 1
	}

	// Resolve any VFS-level symlinks on the initial program path before
	// mapping it to a host path (e.g. /bin/sh -> /bin/busybox).
	resolvedProgram := program
	for i := 0; i < 40; i++ { // POSIX max symlink depth
		meta, err := vv.GetMeta(resolvedProgram)
		if err != nil {
			break
		}
		if meta.Type != "lnk" {
			break
		}
		target := meta.Target
		if len(target) == 0 || target[0] != '/' {
			// relative symlink: resolve against the symlink's directory
			dir := path.Dir(resolvedProgram)
			target = dir + "/" + target
		}
		resolvedProgram = target
	}

	hostProgram := vv.HostPath(resolvedProgram)
	if err := proc.Load(hostProgram); err != nil {
		fmt.Fprintf(os.Stderr, "golinux: loading %s: %v\n", program, err)
		return 1
	}

	code, err := proc.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "golinux: %v\n", err)
		return 1
	}
	return code
}

// autoMount mounts proc, sysfs, and devtmpfs (the latter populated
// with the standard /dev device nodes -- see vfs.EnsureDevfs), like a
// normal Linux boot would before handing off to init. Mirrors
// main.py's _auto_mount.
func autoMount(vv *vfs.VFS) error {
	if err := vv.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return err
	}
	if err := vv.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		return err
	}
	return vv.Mount("devtmpfs", "/dev", "devtmpfs", 0, "")
}

// splitHostSpec splits a "HOST:GUEST" spec (used by -I/--host-file)
// on the LAST colon, so Windows-style host paths with drive letters
// (unlikely here, but matching the Python version's intent) don't
// break the split. Guest paths are always absolute (start with /).
func splitHostSpec(spec string) (host, guest string, ok bool) {
	idx := strings.LastIndex(spec, ":")
	if idx < 0 {
		return "", "", false
	}
	return spec[:idx], spec[idx+1:], true
}

// extractRootfs opens the given tarball, detects gzip/xz compression
// from its magic bytes, and extracts it into the virtual filesystem
// at the given guest dest path.
func extractRootfs(vv *vfs.VFS, path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Sniff magic bytes for decompression.
	magic := make([]byte, 6)
	n, err := f.Read(magic)
	if err != nil && err != io.EOF {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	var reader io.Reader = f
	if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		// gzip magic \x1f\x8b
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	} else if n >= 6 && magic[0] == 0xfd && magic[1] == '7' && magic[2] == 'z' && magic[3] == 'X' && magic[4] == 'Z' && magic[5] == 0x00 {
		// xz magic \xfd7zXZ\x00
		xzr, err := xz.NewReader(f)
		if err != nil {
			return err
		}
		reader = xzr
	}

	fmt.Fprintf(os.Stderr, "Extracting %s to %s...\n", path, dest)
	if err := vv.ExtractTar(reader, dest); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Extraction complete.")
	return nil
}
