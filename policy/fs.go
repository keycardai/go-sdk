package policy

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// WriteFS is the write-side complement to io/fs.FS: it supports creating files
// and making directories. Unload uses WriteFS to expand a bundle onto any
// backing store.
type WriteFS interface {
	// MkdirAll creates path and any missing parents. No-op if path exists.
	MkdirAll(path string, perm fs.FileMode) error
	// Create creates or truncates the file at path and returns a write-closer
	// that commits its content when closed.
	Create(path string) (io.WriteCloser, error)
}

// OsDirFS returns a WriteFS rooted at dir that reads and writes through os.
func OsDirFS(dir string) WriteFS { return &osDirFS{dir: dir} }

type osDirFS struct{ dir string }

func (f *osDirFS) MkdirAll(p string, perm fs.FileMode) error {
	return os.MkdirAll(filepath.Join(f.dir, filepath.FromSlash(p)), perm)
}

func (f *osDirFS) Create(p string) (io.WriteCloser, error) {
	return os.Create(filepath.Join(f.dir, filepath.FromSlash(p)))
}

// VFS is a simple in-memory filesystem that implements both io/fs.FS and
// WriteFS. Files are backed by byte slices; directories are implicit from
// file paths.
type VFS struct {
	mu    sync.RWMutex
	files map[string][]byte
}

var _ fs.FS = (*VFS)(nil)
var _ WriteFS = (*VFS)(nil)

// MkdirAll is a no-op for VFS: directories are implicit from file paths.
func (*VFS) MkdirAll(_ string, _ fs.FileMode) error { return nil }

// Create returns a write-closer that atomically stores its bytes in the VFS on Close.
func (v *VFS) Create(p string) (io.WriteCloser, error) {
	return &vfsWriter{vfs: v, path: p}, nil
}

// Open implements fs.FS.
func (v *VFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	v.mu.RLock()
	defer v.mu.RUnlock()

	if name == "." {
		return &vfsDir{vfs: v, path: "."}, nil
	}
	if content, ok := v.files[name]; ok {
		return &vfsReadFile{name: path.Base(name), data: append([]byte(nil), content...)}, nil
	}
	// treat as directory if any stored file has this as a path prefix
	prefix := name + "/"
	for p := range v.files {
		if strings.HasPrefix(p, prefix) {
			return &vfsDir{vfs: v, path: name}, nil
		}
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// vfsWriter accumulates writes and commits them to the VFS on Close.
type vfsWriter struct {
	vfs  *VFS
	path string
	buf  bytes.Buffer
}

func (w *vfsWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }

func (w *vfsWriter) Close() error {
	data := make([]byte, w.buf.Len())
	copy(data, w.buf.Bytes())
	w.vfs.mu.Lock()
	defer w.vfs.mu.Unlock()
	if w.vfs.files == nil {
		w.vfs.files = make(map[string][]byte)
	}
	w.vfs.files[w.path] = data
	return nil
}

// vfsReadFile is a read-only file backed by a byte slice.
type vfsReadFile struct {
	name string
	data []byte
	pos  int
}

func (f *vfsReadFile) Close() error { return nil }

func (f *vfsReadFile) Read(p []byte) (int, error) {
	if f.pos >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.pos:])
	f.pos += n
	return n, nil
}

func (f *vfsReadFile) Stat() (fs.FileInfo, error) {
	return &vfsFileInfo{name: f.name, size: int64(len(f.data))}, nil
}

// vfsDir is a directory view in a VFS, implementing fs.ReadDirFile.
type vfsDir struct {
	vfs  *VFS
	path string
	pos  int
}

func (d *vfsDir) Close() error { return nil }

func (d *vfsDir) Read(_ []byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.path, Err: fs.ErrInvalid}
}

func (d *vfsDir) Stat() (fs.FileInfo, error) {
	return &vfsFileInfo{name: path.Base(d.path), isDir: true}, nil
}

func (d *vfsDir) ReadDir(n int) ([]fs.DirEntry, error) {
	d.vfs.mu.RLock()
	defer d.vfs.mu.RUnlock()

	prefix := ""
	if d.path != "." {
		prefix = d.path + "/"
	}

	seen := make(map[string]struct{})
	var names []string
	for p := range d.vfs.files {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := p[len(prefix):]
		if idx := strings.IndexByte(rest, '/'); idx >= 0 {
			rest = rest[:idx]
		}
		if _, ok := seen[rest]; !ok {
			seen[rest] = struct{}{}
			names = append(names, rest)
		}
	}
	sort.Strings(names)

	names = names[d.pos:]
	if n > 0 && len(names) > n {
		names = names[:n]
	}
	d.pos += len(names)

	entries := make([]fs.DirEntry, len(names))
	for i, name := range names {
		fullPath := prefix + name
		if content, ok := d.vfs.files[fullPath]; ok {
			entries[i] = fs.FileInfoToDirEntry(&vfsFileInfo{name: name, size: int64(len(content))})
		} else {
			entries[i] = fs.FileInfoToDirEntry(&vfsFileInfo{name: name, isDir: true})
		}
	}
	return entries, nil
}

// vfsFileInfo implements fs.FileInfo for VFS entries.
type vfsFileInfo struct {
	name  string
	size  int64
	isDir bool
}

func (fi *vfsFileInfo) Name() string { return fi.name }
func (fi *vfsFileInfo) Size() int64  { return fi.size }
func (fi *vfsFileInfo) Mode() fs.FileMode {
	if fi.isDir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (fi *vfsFileInfo) ModTime() time.Time { return time.Time{} }
func (fi *vfsFileInfo) IsDir() bool        { return fi.isDir }
func (fi *vfsFileInfo) Sys() any           { return nil }
