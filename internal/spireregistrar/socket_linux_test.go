//go:build linux

package spireregistrar

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPrivateAdminUDSServerUIDAndNonSocketRefusal(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0770); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := DialServerSocket(ctx, path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if _, err := DialServerSocket(ctx, path, uint32(os.Getuid()+1)); err == nil {
		t.Fatal("wrong server UID accepted")
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := DialServerSocket(ctx, path, uint32(os.Getuid())); err == nil {
		t.Fatal("world-accessible admin socket accepted")
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := DialServerSocket(ctx, fifo, uint32(os.Getuid())); err == nil {
		t.Fatal("FIFO accepted as admin socket")
	}
}
