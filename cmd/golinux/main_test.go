package main

import (
	"os"
	"path/filepath"
	"testing"

	"golinux/internal/vfs"
)

func TestEnsureHostResolver(t *testing.T) {
	t.Run("imports host resolver when guest config is absent", func(t *testing.T) {
		vv := newResolverTestVFS(t)
		hostPath := filepath.Join(t.TempDir(), "resolv.conf")
		want := "nameserver 192.0.2.53\noptions timeout:2\n"
		if err := os.WriteFile(hostPath, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ensureHostResolver(vv, hostPath); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(vv.HostPath("/etc/resolv.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("resolver contents = %q, want %q", got, want)
		}
	})

	t.Run("preserves guest resolver", func(t *testing.T) {
		vv := newResolverTestVFS(t)
		guestPath := filepath.Join(t.TempDir(), "guest-resolv.conf")
		custom := "nameserver 192.0.2.54\n"
		if err := os.WriteFile(guestPath, []byte(custom), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := vv.ImportHostFile(guestPath, "/etc/resolv.conf", 0o644); err != nil {
			t.Fatal(err)
		}
		hostPath := filepath.Join(t.TempDir(), "host-resolv.conf")
		if err := os.WriteFile(hostPath, []byte("nameserver 192.0.2.53\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ensureHostResolver(vv, hostPath); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(vv.HostPath("/etc/resolv.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != custom {
			t.Fatalf("resolver contents = %q, want preserved config %q", got, custom)
		}
	})

	t.Run("ignores a missing host resolver file", func(t *testing.T) {
		vv := newResolverTestVFS(t)
		missingPath := filepath.Join(t.TempDir(), "missing-resolv.conf")
		if err := ensureHostResolver(vv, missingPath); err != nil {
			t.Fatal(err)
		}
		if vv.Exists("/etc/resolv.conf") {
			t.Fatal("unexpectedly created guest resolver file")
		}
	})
}

func newResolverTestVFS(t *testing.T) *vfs.VFS {
	t.Helper()
	vv, err := vfs.New(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := vv.Makedirs("/etc", 0o755); err != nil {
		t.Fatal(err)
	}
	return vv
}
