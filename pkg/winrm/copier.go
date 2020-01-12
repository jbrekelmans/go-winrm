package winrm

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/karrick/godirwalk"
	log "github.com/sirupsen/logrus"
)

const parentPrefix = ".." + string(os.PathSeparator)
const dotBase64 = ".b64"
const shellUtilizationLogLevel = log.DebugLevel

var regexpRemoteFileThatDoesNotNeedEscaping = regexp.MustCompile(`^[a-zA-Z0-9]:(?:\\|(?:\\[a-zA-Z0-9-_\. ^&]+)+)$`)
var regexpFileBasenameThatDoesNotNeedEscaping = regexp.MustCompile(`^[a-zA-Z0-9-_\. ^&]+$`)

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

type stats struct {
	bytesCopied           int64
	startTime             time.Time
	lastReportBytesCopied int64
	lastReportTime        time.Time
}

type FileTreeCopier struct {
	errors        []error
	errorsMutex   sync.Mutex
	localRoot     string
	localRootStat os.FileInfo
	remoteRoot    string
	// One shell for each winrs worker.
	shells map[*Shell]bool
	// The waitGroup counter is incremented for each winrsTask that is created, and once for each scanDirTask that is created.
	waitGroup        sync.WaitGroup
	winrsTaskQueue   chan *winrsTask
	scanDirWorkers   int
	scanDirTaskQueue chan *scanDirTask
	stats            stats
	done             chan struct{}
}

// NewFileTreeCopier creates a new file copier. remoteRoot must be a cleaned absolute Windows file path that starts
// with a drive letter.
// Limitations:
// 1. if localRoot is a regular file then the remote directory to which it would be copied must not contain an entry with a case-insensitive
//    equal name, or a name case-insensitive equal to the base name of localRoot concatenated with .b64
// 2. after cleaning localRoot (filepath.Clean), it should not contain any characters outside the regular expression class [a-zA-Z0-9-_\. ],
//    because escaping such file names is not supported.
func NewFileTreeCopier(shells []*Shell, scanDirWorkers int, remoteRoot, localRoot string) (*FileTreeCopier, error) {
	f := &FileTreeCopier{
		localRoot:      localRoot,
		remoteRoot:     remoteRoot,
		scanDirWorkers: scanDirWorkers,
		shells:         map[*Shell]bool{},
	}
	if f.scanDirWorkers < 1 {
		return nil, fmt.Errorf("scanDirWorkers must be at least 1")
	}
	if len(shells) == 0 {
		return nil, fmt.Errorf("shells cannot be empty")
	}
	for _, shell := range shells {
		if shell == nil {
			return nil, fmt.Errorf("shells contains a nil shell")
		}
		if _, ok := f.shells[shell]; ok {
			return nil, fmt.Errorf("shells contains duplicate shell objects")
		}
		f.shells[shell] = true
	}
	if filepath.IsAbs(f.localRoot) {
		return nil, fmt.Errorf("localRoot must be a relative file")
	}
	f.localRoot = filepath.Clean(f.localRoot)
	if f.localRoot == ".." || strings.HasPrefix(f.localRoot, parentPrefix) {
		return nil, fmt.Errorf("localRoot must be a relative file within the current working directory")
	}
	remoteFile := f.getRemoteFile(f.localRoot)
	if !regexpRemoteFileThatDoesNotNeedEscaping.MatchString(remoteFile) {
		return nil, fmt.Errorf("either remoteRoot is not an absolute cleaned Windows path starting with a drive letter, or remoteRoot or "+
			"localRoot has a path component that contains an unsupported character. The regexp for validating path "+
			"components is %s", regexpFileBasenameThatDoesNotNeedEscaping.String())
	}
	var err error
	f.localRootStat, err = os.Lstat(f.localRoot)
	if err != nil {
		return nil, err
	}
	f.winrsTaskQueue = make(chan *winrsTask, len(f.shells)*2)
	f.scanDirTaskQueue = make(chan *scanDirTask, len(f.shells))
	f.done = make(chan struct{})
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
	log.Tracef(commandAndArgs[0])
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

func validateFileBasename(fileBasename string) error {
	if strings.HasSuffix(fileBasename, dotBase64) {
		return fmt.Errorf("basename of file system entry %#v has reserved suffix %#v", fileBasename, dotBase64)
	}
	if !regexpFileBasenameThatDoesNotNeedEscaping.MatchString(fileBasename) {
		return fmt.Errorf("basename of file system entry %#v is not supported. The regexp used for "+
			"validation is %s", fileBasename, regexpFileBasenameThatDoesNotNeedEscaping.String())
	}
	return nil
}

func (f *FileTreeCopier) scanDirWorker(id int) {
	for {
		log.Debugf("scanDirWorker(%d): pulling task from queue", id)
		t, ok := <-f.scanDirTaskQueue
		if !ok {
			break
		}
		scanner, err := godirwalk.NewScanner(t.LocalFile)
		if err != nil {
			f.addError(err)
		} else {
			for scanner.Scan() {
				err := validateFileBasename(scanner.Name())
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
	log.Debugf("scanDirWorker(%d): goroutine finishing", id)
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
	f.stats.startTime = time.Now()
	f.stats.lastReportTime = f.stats.startTime
	if f.localRootStat.Mode()&os.ModeType == 0 {
		// root is a regular file, simple case
		var shell *Shell
		for s := range f.shells {
			shell = s
			break
		}
		w := newWinrsWorker(f, 0, shell)
		remoteFile := f.getRemoteFile(f.localRoot)
		i := strings.LastIndex(remoteFile, "\\")
		// i must be greater than 0, by NewFileTreeCopier precondition
		j := strings.LastIndex(remoteFile[:i], "\\")
		if j >= 0 {
			err := w.makeDirectories(remoteFile[:i], true)
			if err != nil {
				return err
			}
		} else {
			// optimization: do not attempt to make the directory if its the root.
		}
		return w.copyFile(f.localRoot, remoteFile)
	} else if !f.localRootStat.IsDir() {
		// ignore everything that is not a regular file or directory
		return nil
	}
	// root is a directory
	remoteFile := f.getRemoteFile(f.localRoot)
	if strings.HasSuffix(remoteFile, "\\") {
		// the constructor precondition ensures that this is the correct check for detecting if
		// remoteFile is the root (e.g. C:\)
		// optimization: do not attempt to make the directory if its the root.
		f.waitGroup.Add(1)
		f.scanDirTaskQueue <- &scanDirTask{
			LocalFile: f.localRoot,
		}
	} else {
		f.createMkdirTaskForRootOfFileTreeToCopy(f.localRoot)
	}
	i := 0
	for shell := range f.shells {
		winrsWorker := newWinrsWorker(f, i, shell)
		go winrsWorker.Run()
		i++
	}
	for i := 0; i < f.scanDirWorkers; i++ {
		go f.scanDirWorker(i)
	}
	go f.reportLoop()
	f.waitGroup.Wait()
	close(f.winrsTaskQueue)
	close(f.scanDirTaskQueue)
	f.done <- struct{}{}
	elapsedSeconds := time.Since(f.stats.startTime).Seconds()
	overallBytesPerSecond := float64(f.stats.bytesCopied) / elapsedSeconds
	log.Infof("copied file tree with %d errors in %2f seconds (upload speed = %.0f bytes per second)", len(f.errors), elapsedSeconds, overallBytesPerSecond)
	if len(f.errors) == 0 {
		return nil
	}
	return f.errors[0]
}

func (f *FileTreeCopier) reportLoop() {
	for {
		select {
		case <-f.done:
			break
		case <-time.After(time.Second * 5):
			now := time.Now()
			v := atomic.LoadInt64(&f.stats.bytesCopied)
			bytesCopied := v - f.stats.lastReportBytesCopied
			elapsedTime := now.Sub(f.stats.lastReportTime)
			f.stats.lastReportBytesCopied = v
			f.stats.lastReportTime = now
			bytesCopiedPerSecond := float64(bytesCopied) / elapsedTime.Seconds()
			log.Infof("stats: upload speed = %.0f bytes per second", bytesCopiedPerSecond)
		}
	}
	log.Debugf("reportLoop: goroutine finishing")
}

func (f *FileTreeCopier) getRemoteFile(localFile string) string {
	remoteFile := f.remoteRoot
	if localFile != "." {
		if !strings.HasSuffix(remoteFile, "\\") {
			remoteFile += "\\"
		}
		if os.PathSeparator == '\\' {
			remoteFile += localFile
		} else {
			remoteFile += strings.ReplaceAll(localFile, "/", "\\")
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

type winrsFileCopier struct {
	finalizeCommand          string
	attemptedFinalizeCommand bool
	localFile                string
	remoteFile               string
	remoteFileDotBase64      string
	w                        *winrsWorker
}

func newWinrsFileCopier(w *winrsWorker, localFile, remoteFile string) *winrsFileCopier {
	return &winrsFileCopier{
		w:                   w,
		localFile:           localFile,
		remoteFile:          remoteFile,
		remoteFileDotBase64: remoteFile + dotBase64,
	}
}

func (w *winrsWorker) copyFile(localFile, remoteFile string) error {
	return newWinrsFileCopier(w, localFile, remoteFile).Run()
}

func (w *winrsFileCopier) getFinalizeCommand() string {
	if w.finalizeCommand == "" {
		w.finalizeCommand = fmt.Sprintf(`certutil -decode "%s" "%s"&&del /q "%s"`, w.remoteFileDotBase64, w.remoteFile, w.remoteFileDotBase64)
	}
	return w.finalizeCommand
}

func (w *winrsFileCopier) Run() error {
	numberOfChunksCopied := 0
	maxCommandSize := w.w.shell.MaxSizeOfCommandWithZeroArguments()
	commandPrefix := `echo `
	// Used for every chunk except the first one.
	commandSuffix1 := `>>"` + w.remoteFileDotBase64 + `"`
	// Used for the first chunk.
	commandSuffix2 := `>"` + w.remoteFileDotBase64 + `"`
	maxChunkBase64Size := maxCommandSize - len(commandPrefix) - len(commandSuffix1)
	// We split base64 data over a number of chunks, but as an optimization require base64 chunk sizes are multiples of 4.
	// For the first chunk, maxChunkBase64Size is off by one character, but we do not care about this (see commandSuffix1 and commandSuffix2).
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
	fd, err := os.Open(w.localFile)
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
				if numberOfChunksCopied == 0 {
					return w.emptyFile()
				}
				break
			}
			base64.StdEncoding.Encode(commandBuffer[commandBufferSize:], readBuffer[:readBufferLength])
			commandBufferSize += base64.StdEncoding.EncodedLen(readBufferLength)
		} else {
			readBufferLengthMod3 := readBufferLength % 3
			base64.StdEncoding.Encode(commandBuffer[commandBufferSize:], readBuffer[:readBufferLength-readBufferLengthMod3])
			commandBufferSize += base64.StdEncoding.EncodedLen(readBufferLength - readBufferLengthMod3)
			atomic.AddInt64(&w.w.f.stats.bytesCopied, int64(readBufferLength-readBufferLengthMod3))
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
		if numberOfChunksCopied == 0 {
			commandBufferSize += copy(commandBuffer[commandBufferSize:], commandSuffix2)
		} else {
			commandBufferSize += copy(commandBuffer[commandBufferSize:], commandSuffix1)
		}
		if isEOF {
			if maxCommandSize-commandBufferSize >= 2+len(w.getFinalizeCommand()) {
				commandBufferSize += copy(commandBuffer[commandBufferSize:], "&&")
				commandBufferSize += copy(commandBuffer[commandBufferSize:], w.getFinalizeCommand())
				w.attemptedFinalizeCommand = true
			}
		}
		command := string(commandBuffer[:commandBufferSize])
		err = w.w.RunCommand([]string{command})
		numberOfChunksCopied++
		if err != nil {
			return err
		}
		if isEOF {
			break
		}
	}
	if !w.attemptedFinalizeCommand {
		w.attemptedFinalizeCommand = true
		err = w.w.RunCommand([]string{w.getFinalizeCommand()})
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *winrsFileCopier) emptyFile() error {
	command := fmt.Sprintf(`copy /y NUL "%s"`, w.remoteFile)
	err := w.w.RunCommand([]string{command})
	if err != nil {
		return fmt.Errorf("error while creating empty file %#v: %w", w.remoteFile, err)
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
