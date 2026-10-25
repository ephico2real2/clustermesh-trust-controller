//go:build linux

package spireregistrar

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// DialServerSocket never falls back to TCP. The socket mount is shared only
// inside the SPIRE server Pod; same-UID/group components there are the SPIRE TCB.
func DialServerSocket(ctx context.Context, path string, serverUID uint32) (net.Conn, error) {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	pst, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0007 != 0 || (pst.Uid != 0 && pst.Uid != serverUID) {
		return nil, errors.New("SPIRE admin socket parent is not a private server-owned directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0007 != 0 || st.Uid != serverUID {
		return nil, errors.New("SPIRE admin endpoint is not a private owned socket")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, errors.New("SPIRE transport is not Unix")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, err
	}
	var cred *unix.Ucred
	var peerErr error
	if err = raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || peerErr != nil || cred == nil || cred.Uid != serverUID {
		conn.Close()
		return nil, errors.New("SPIRE Unix server credential mismatch")
	}
	return conn, nil
}
