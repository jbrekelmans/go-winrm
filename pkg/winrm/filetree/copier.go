package filetree

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karrick/godirwalk"
	zenwinrm "github.com/masterzen/winrm"
)

const parentPrefix = ".." + string(os.PathSeparator)

type FileTreeCopier struct {
	localRoot  string
	remoteRoot string
	shell      *zenwinrm.Shell
}

func NewFileTreeCopier(shell *zenwinrm.Shell, remoteRoot, localRoot string) (*FileTreeCopier, error) {
	if shell == nil {
		return nil, fmt.Errorf("shell must not be nil")
	}
	if filepath.IsAbs(localRoot) {
		return nil, fmt.Errorf("localRoot must be a relative file")
	}
	localRoot = filepath.Clean(localRoot)
	if localRoot == ".." || strings.HasPrefix(localRoot, parentPrefix) {
		return nil, fmt.Errorf("localRoot must be a relative file within the current working directory")
	}
	f := &FileTreeCopier{
		localRoot:  localRoot,
		remoteRoot: remoteRoot,
		shell:      shell,
	}
	return f, nil
}

func (f *FileTreeCopier) Run() error {
	return godirwalk.Walk(f.localRoot, &godirwalk.Options{
		AllowNonDirectory:   true,
		Callback:            f.walkCallback,
		FollowSymbolicLinks: false,
		Unsorted:            true,
	})
}

func (f *FileTreeCopier) walkCallback(osPathname string, de *godirwalk.Dirent) error {
	if !de.IsRegular() {
		return nil
	}
	remoteName := f.remoteRoot
	if osPathname != "." {
		if os.PathSeparator == '\\' {
			remoteName += "\\" + osPathname
		} else {
			remoteName += "\\" + strings.ReplaceAll(osPathname, "/", "\\")
		}
	}
	fd, err := os.Open(osPathname)
	if err != nil {
		return err
	}
	defer fd.Close()
	f.shell.Execute("echo %s >> bla.file")
	return err
}
