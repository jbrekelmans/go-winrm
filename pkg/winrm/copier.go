package winrm

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/karrick/godirwalk"
	log "github.com/sirupsen/logrus"
)

const parentPrefix = ".." + string(os.PathSeparator)
const dotBase64 = ".b64"
const shellUtilizationLogLevel = log.DebugLevel

type winrsTaskType int

const (
	winrsTaskTypeMakeDirectories winrsTaskType = iota
	winrsTaskTypeCopyFile
)

type winrsTaskStatus int

const (
	// pending means that the task is a dependant of another task, the task is in winrsTaskQueue or the task has been picked
	// up by a worker goroutine (but is not yet in progress)
	winrsTaskStatusPending winrsTaskStatus = iota
	winrsTaskStatusInProgress
	winrsTaskStatusCompleted
)

type winrsTask struct {
	Type      winrsTaskType
	LocalFile string
}

type scanDirTask struct {
	LocalFile string
}

type FileTreeCopier struct {
	errors        []error
	errorsMutex   sync.Mutex
	localRoot     string
	localRootStat os.FileInfo
	remoteRoot    string
	shell         *Shell
	// The waitGroup counter is incremented for each winrsTask that is created, and once for each scanDirTask that is created.
	waitGroup        sync.WaitGroup
	winrsTaskQueue   chan *winrsTask
	scanDirTaskQueue chan *scanDirTask
	winrsWorkerCount int
}

// NewFileTreeCopier creates a new file copier. remoteRoot must be a cleaned absolute Windows file path that does not
// start with an UNC prefix.
func NewFileTreeCopier(shell *Shell, remoteRoot, localRoot string) (*FileTreeCopier, error) {
	if shell == nil {
		return nil, fmt.Errorf("shell must not be nil")
	}
	if filepath.IsAbs(localRoot) {
		return nil, fmt.Errorf("localRoot must be a relative file")
	}
	f := &FileTreeCopier{
		localRoot:  localRoot,
		remoteRoot: remoteRoot,
		shell:      shell,
		// Currently set to one because we only have one shell, but the intention is to use many shells at once.
		winrsWorkerCount: 1,
	}
	f.localRoot = filepath.Clean(f.localRoot)
	if f.localRoot == ".." || strings.HasPrefix(f.localRoot, parentPrefix) {
		return nil, fmt.Errorf("localRoot must be a relative file within the current working directory")
	}
	var err error
	err = validateFileName(f.localRoot)
	if err != nil {
		return nil, err
	}
	f.localRootStat, err = os.Lstat(f.localRoot)
	if err != nil {
		return nil, err
	}
	f.winrsTaskQueue = make(chan *winrsTask, f.winrsWorkerCount*2)
	f.scanDirTaskQueue = make(chan *scanDirTask, 2)
	return f, nil
}

type winrsWorker struct {
	id           int
	f            *FileTreeCopier
	shell        *Shell
	shellUseTime time.Duration
}

func newWinrsWorker(f *FileTreeCopier, id int, shell *Shell) *winrsWorker {
	return &winrsWorker{
		id:    id,
		f:     f,
		shell: shell,
	}
}

func (w *winrsWorker) RunCommand(commandAndArgs []string) error {
	if !log.IsLevelEnabled(shellUtilizationLogLevel) {
		return RunCommand(w.shell, commandAndArgs)
	}
	s := time.Now()
	err := RunCommand(w.shell, commandAndArgs)
	w.shellUseTime += time.Since(s)
	return err
}

func (w *winrsWorker) Run() {
	startTime := time.Now()
	for {
		log.Debugf("winrsWorker(%d): pulling task from queue", w.id)
		t, ok := <-w.f.winrsTaskQueue
		if !ok {
			break
		}
		switch t.Type {
		case winrsTaskTypeMakeDirectories:
			remoteFile := w.f.getRemoteFile(t.LocalFile)
			err := w.makeDirectories(remoteFile, remoteFile == w.f.remoteRoot)
			if err != nil {
				log.Errorf("mkdir %#v failed: %v", remoteFile, err)
				w.f.addError(err)
			} else {
				log.Infof("mkdir %#v succeeded", remoteFile)
			}
			w.f.scanDirTaskQueue <- &scanDirTask{
				LocalFile: t.LocalFile,
			}
			log.Debugf("queued scandir %#v", t.LocalFile)
		case winrsTaskTypeCopyFile:
			remoteFile := w.f.getRemoteFile(t.LocalFile)
			err := w.copyFile(t.LocalFile, remoteFile)
			if err != nil {
				log.Errorf("cp %#v failed: %v", remoteFile, err)
				w.f.addError(err)
			} else {
				log.Infof("cp %#v succeeded", remoteFile)
			}
			w.f.waitGroup.Done()
		default:
			panic(fmt.Errorf("winrsTask has unknown type %d", t.Type))
		}
	}
	if log.IsLevelEnabled(shellUtilizationLogLevel) {
		elapsedTime := time.Since(startTime)
		elapsedSeconds := elapsedTime.Seconds()
		shellUsePercentage := w.shellUseTime.Seconds() / elapsedSeconds * 100.0
		log.StandardLogger().Logf(shellUtilizationLogLevel, "winrsWorker(%d): goroutine finishing in %.2f seconds (shell utilization %.2f%%)", w.id, elapsedSeconds, shellUsePercentage)
	}
}

func (f *FileTreeCopier) addError(err error) {
	f.errorsMutex.Lock()
	defer f.errorsMutex.Unlock()
	f.errors = append(f.errors, err)
}

func validateFileName(file string) error {
	if strings.HasSuffix(file, dotBase64) {
		return fmt.Errorf("base name of file %#v has reserved suffix %#v", file, dotBase64)
	}
	return nil
}

func (f *FileTreeCopier) scanDirWorker() {
	for {
		log.Debugf("scanDirWorker: pulling task from queue")
		t, ok := <-f.scanDirTaskQueue
		if !ok {
			break
		}
		scanner, err := godirwalk.NewScanner(t.LocalFile)
		if err != nil {
			f.addError(err)
		} else {
			for scanner.Scan() {
				err := validateFileName(scanner.Name())
				if err != nil {
					f.addError(err)
					break
				}
				childLocalFileInfo, err := scanner.Dirent()
				if err != nil {
					f.addError(err)
					break
				}
				childLocalFile := filepath.Join(t.LocalFile, scanner.Name())
				switch {
				case err != nil:
					f.addError(err)
					break
				case childLocalFileInfo.IsDir():
					f.scanDirWorkerDir(t.LocalFile, childLocalFile)
				case childLocalFileInfo.IsRegular():
					f.scanDirWorkerRegularFile(t.LocalFile, childLocalFile)
				}
			}
			if err := scanner.Err(); err != nil {
				f.addError(err)
			}
		}
		f.waitGroup.Done()
	}
	log.Debugf("scanDirWorker: goroutine finishing")
}

func (f *FileTreeCopier) scanDirWorkerDir(localFileParent, localFile string) {
	t := &winrsTask{
		Type:      winrsTaskTypeMakeDirectories,
		LocalFile: localFile,
	}
	f.waitGroup.Add(1)
	f.winrsTaskQueue <- t
	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debugf("queued mkdir %#v", f.getRemoteFile(localFile))
	}
}

func (f *FileTreeCopier) scanDirWorkerRegularFile(localFileParent, localFile string) {
	t := &winrsTask{
		Type:      winrsTaskTypeCopyFile,
		LocalFile: localFile,
	}
	f.waitGroup.Add(1)
	f.winrsTaskQueue <- t
	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debugf("queued cp %#v", f.getRemoteFile(localFile))
	}
}

func (f *FileTreeCopier) Run() error {
	if f.localRootStat.Mode()&os.ModeType == 0 {
		// root is a regular file, simple case
		w := newWinrsWorker(f, 0, f.shell)
		remoteFile := f.getRemoteFile(f.localRoot)
		i := strings.LastIndex(remoteFile, "\\")
		// i must be greater than 0, by constructor precondition
		j := strings.LastIndex(remoteFile[:i], "\\")
		if j >= 0 { // optimization: do not attempt to make the directory if its the root.
			err := w.makeDirectories(remoteFile[:i], true)
			if err != nil {
				return err
			}
		}
		return w.copyFile(f.localRoot, f.getRemoteFile(f.localRoot))
	} else if !f.localRootStat.IsDir() {
		// ignore everything that is not a regular file or directory
		return nil
	}
	// root is a directory
	remoteFile := f.getRemoteFile(f.localRoot)
	if strings.HasSuffix(remoteFile, "\\") {
		// the constructor precondition ensures that this is the correct check for detecting if
		// remoteFile is the root
		// optimization: do not attempt to make the directory if its the root.
		f.waitGroup.Add(1)
		f.scanDirTaskQueue <- &scanDirTask{
			LocalFile: f.localRoot,
		}
	} else {
		f.createMkdirTaskForRootOfFileTreeToCopy(f.localRoot)
	}
	for i := 0; i < f.winrsWorkerCount; i++ {
		winrsWorker := newWinrsWorker(f, i, f.shell)
		go winrsWorker.Run()
	}
	go f.scanDirWorker()
	f.waitGroup.Wait()
	log.Debugf("run: all tasks completed")
	close(f.winrsTaskQueue)
	close(f.scanDirTaskQueue)
	if len(f.errors) == 0 {
		return nil
	}
	log.Infof("got %d errors while copying file tree", len(f.errors))
	return f.errors[0]
}

func (f *FileTreeCopier) getRemoteFile(localFile string) string {
	remoteFile := f.remoteRoot
	if localFile != "." {
		if os.PathSeparator == '\\' {
			remoteFile += "\\" + localFile
		} else {
			remoteFile += "\\" + strings.ReplaceAll(localFile, "/", "\\")
		}
	}
	return remoteFile
}

func (f *FileTreeCopier) createMkdirTaskForRootOfFileTreeToCopy(localFile string) {
	t := &winrsTask{
		Type:      winrsTaskTypeMakeDirectories,
		LocalFile: localFile,
	}
	f.waitGroup.Add(1)
	f.winrsTaskQueue <- t
	if log.IsLevelEnabled(log.DebugLevel) {
		log.Debugf("queued mkdir %#v", f.getRemoteFile(localFile))
	}
}

func (w *winrsWorker) copyFile(localFile, remoteFile string) error {
	var err error
	i := strings.LastIndex(remoteFile, "\\")
	// i must be >= 0 since f.remoteRoot is absolute
	remoteFileDir := remoteFile[:i]
	remoteFileDotBase64 := remoteFile + dotBase64
	err = w.RunCommand([]string{fmt.Sprintf(`copy /y NUL "%s"`, remoteFileDotBase64)})
	if err != nil {
		return fmt.Errorf("error while creating empty file %#v: %w", remoteFileDir, err)
	}
	err = w.copyFileContentAsBase64(localFile, remoteFileDotBase64)
	if err != nil {
		return fmt.Errorf("error while copying file content as base64: %w", err)
	}
	err = w.RunCommand([]string{fmt.Sprintf(`certutil -decode "%s" "%s" && del /q "%s"`, remoteFileDotBase64, remoteFile, remoteFileDotBase64)})
	if err != nil {
		return fmt.Errorf("error while base64 decoding file: %w", err)
	}
	return nil
}

func (w *winrsWorker) copyFileContentAsBase64(localFile, remoteFile string) error {
	maxCommandSize := w.shell.MaxSizeOfCommandWithZeroArguments()
	commandPrefix := "<nul set /p dummyName=\""
	commandSuffix := "\" >> \"" + remoteFile + "\""
	maxChunkBase64Size := maxCommandSize - len(commandPrefix) - len(commandSuffix)
	// We split base64 data over a number of chunks, but as an optimization require base64 chunk sizes are multiples of 4.
	if maxChunkBase64Size < 4 {
		return fmt.Errorf("envelope size is too small")
	}
	// The maximum number of bytes that can fit into one chunk.
	maxChunkSize := maxChunkBase64Size / 4 * 3
	// Add padding of 2 bytes so that we can rotate the readBuffer to ensure all chunks except the last encode multiples of 3
	// bytes.
	readBuffer := make([]byte, maxChunkSize+2)
	readBufferLength := 0
	commandBuffer := make([]byte, maxCommandSize)
	copy(commandBuffer[0:len(commandPrefix)], commandPrefix)
	fd, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer fd.Close()
	for {
		n, err := fd.Read(readBuffer[readBufferLength:maxChunkSize])
		readBufferLength += n
		commandBufferSize := len(commandPrefix)
		isEOF := false
		if err != nil {
			if err != io.EOF {
				return err
			}
			isEOF = true
			if readBufferLength == 0 {
				break
			}
			base64.StdEncoding.Encode(commandBuffer[commandBufferSize:], readBuffer[:readBufferLength])
			commandBufferSize += base64.StdEncoding.EncodedLen(readBufferLength)
		} else {
			readBufferLengthMod3 := readBufferLength % 3
			base64.StdEncoding.Encode(commandBuffer[commandBufferSize:], readBuffer[:readBufferLength-readBufferLengthMod3])
			commandBufferSize += base64.StdEncoding.EncodedLen(readBufferLength - readBufferLengthMod3)
			switch readBufferLengthMod3 {
			case 0:
				readBufferLength = 0
			case 1:
				readBuffer[0] = readBuffer[readBufferLength-1]
				readBufferLength = 1
			case 2:
				readBuffer[0] = readBuffer[readBufferLength-2]
				readBuffer[1] = readBuffer[readBufferLength-1]
				readBufferLength = 2
			}
		}
		commandBufferSize += copy(commandBuffer[commandBufferSize:], commandSuffix)
		var commandAndArgsBuffer [1]string
		commandAndArgsBuffer[0] = string(commandBuffer[:commandBufferSize])
		err = w.RunCommand(commandAndArgsBuffer[:])
		if err != nil {
			return err
		}
		if isEOF {
			break
		}
	}
	return nil
}

func (w *winrsWorker) makeDirectories(remoteFile string, checkIfExists bool) error {
	var command string
	if checkIfExists {
		remoteFileWithSlash := remoteFile + "\\"
		command = fmt.Sprintf(`if not exist "%s" md "%s"`, remoteFileWithSlash, remoteFile)
	} else {
		command = fmt.Sprintf(`md "%s"`, remoteFile)
	}
	return w.RunCommand([]string{command})
}
