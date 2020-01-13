package winrm

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

const pipeHasEnded = "The pipe has been ended."
const pipeIsBeingClosed = "The pipe is being closed."
const parentPrefix = ".." + string(os.PathSeparator)
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
//    equal name.
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
	f.scanDirTaskQueue = make(chan *scanDirTask, 10000)
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

func (w *winrsWorker) RunCommand(command string) error {
	log.Tracef(command)
	if !log.IsLevelEnabled(shellUtilizationLogLevel) {
		return RunCommand(w.shell, command, nil, true, false)
	}
	s := time.Now()
	err := RunCommand(w.shell, command, nil, true, false)
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

func (w *winrsWorker) copyFile(localFile, remoteFile string) error {
	commandAndArgs := FormatPowershellScriptCommandLine(`begin {
	$path = '` + remoteFile + `'
	$DebugPreference = "Continue"
	$ErrorActionPreference = "Stop"
	Set-StrictMode -Version 2
	$fd = [System.IO.File]::Create($path)
	$sha256 = [System.Security.Cryptography.SHA256CryptoServiceProvider]::Create()
	$bytes = @() #initialize for empty file case
}
process {
	$bytes = [System.Convert]::FromBase64String($input)
	$sha256.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0) | Out-Null
	$fd.Write($bytes, 0, $bytes.Length)
}
end {
	$sha256.TransformFinalBlock($bytes, 0, 0) | Out-Null
	$hash = [System.BitConverter]::ToString($sha256.Hash).Replace("-", "").ToLowerInvariant()
	$fd.Close()
	Write-Output "{""sha256"":""$hash""}"
}`)
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef(strings.Join(commandAndArgs, " "))
	}
	stat, err := os.Lstat(localFile)
	if err != nil {
		return err
	}
	sha256DigestLocalComputer := sha256.New()
	sha256DigestLocal := ""
	sha256DigestRemote := ""
	fileSize := stat.Size()
	bytesCopied := int64(0)
	fdClosed := false
	fd, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer func() {
		if !fdClosed {
			_ = fd.Close()
			fdClosed = true
		}
	}()
	s := time.Now()
	cmd, err := w.shell.StartCommand(commandAndArgs[0], commandAndArgs[1:], false, true)
	if err != nil {
		return err
	}
	// Since we are passing data over a powershell pipe, we encode the data as lines of base64 (each line is terminated by a carriage return +
	// line feed sequence, hence the -2)
	bufferCapacity := (w.shell.Client().SendInputMax() - 2) / 4 * 3
	base64LineBufferCapacity := bufferCapacity/3*4 + 2
	base64LineBuffer := make([]byte, base64LineBufferCapacity)
	base64LineBuffer[base64LineBufferCapacity-2] = '\r'
	base64LineBuffer[base64LineBufferCapacity-1] = '\n'
	buffer := make([]byte, bufferCapacity)
	bufferLength := 0
	ended := false
	for {
		var n int
		n, err = fd.Read(buffer)
		bufferLength += n
		if err != nil {
			break
		}
		if bufferLength == bufferCapacity {
			base64.StdEncoding.Encode(base64LineBuffer, buffer)
			bytesCopied += int64(bufferLength)
			_, _ = sha256DigestLocalComputer.Write(buffer)
			if bytesCopied >= fileSize {
				ended = true
				sha256DigestLocal = hex.EncodeToString(sha256DigestLocalComputer.Sum(nil))
			}
			err := cmd.SendInput(base64LineBuffer, ended)
			atomic.AddInt64(&w.f.stats.bytesCopied, int64(bufferLength))
			bufferLength = 0
			if err != nil {
				w.f.addError(err)
			}
		}
	}
	fd.Close()
	fdClosed = true
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		return err
	}
	if !ended {
		_, _ = sha256DigestLocalComputer.Write(buffer[:bufferLength])
		sha256DigestLocal = hex.EncodeToString(sha256DigestLocalComputer.Sum(nil))
		base64.StdEncoding.Encode(base64LineBuffer, buffer[:bufferLength])
		i := base64.StdEncoding.EncodedLen(bufferLength)
		base64LineBuffer[i] = '\r'
		base64LineBuffer[i+1] = '\n'
		err = cmd.SendInput(base64LineBuffer[:i+2], true)
		if err != nil {
			if !strings.Contains(err.Error(), pipeHasEnded) && !strings.Contains(err.Error(), pipeIsBeingClosed) {
				cmd.Signal()
				return err
			}
			// ignore pipe errors that results from passing true to cmd.SendInput
		}
		ended = true
		bytesCopied += int64(bufferLength)
		atomic.AddInt64(&w.f.stats.bytesCopied, int64(bufferLength))
		bufferLength = 0
	}
	var wg sync.WaitGroup
	wg.Add(2)
	var errors []error
	var errorsMutex sync.Mutex
	go func() {
		_, err = io.Copy(os.Stderr, cmd.Stderr)
		if err != nil {
			errWrapped := fmt.Errorf("error while copying command's stderr to own stderr: %w", err)
			errorsMutex.Lock()
			errors = append(errors, errWrapped)
			errorsMutex.Unlock()
		}
		wg.Done()
	}()
	go func() {
		scanner := bufio.NewScanner(cmd.Stdout)
		for scanner.Scan() {
			os.Stdout.Write(append(scanner.Bytes(), '\n'))
			var output struct {
				Sha256 string `json:"sha256"`
			}
			if json.Unmarshal(scanner.Bytes(), &output) == nil {
				sha256DigestRemote = output.Sha256
			}
		}
		if scanner.Err() != nil {
			errWrapped := fmt.Errorf("error while copying command's stdout to own stdout: %w", err)
			errorsMutex.Lock()
			errors = append(errors, errWrapped)
			errorsMutex.Unlock()
		}
		wg.Done()
	}()
	cmd.Wait()
	if cmd.ExitCode() != 0 {
		err := fmt.Errorf("command unexpectedly exited with code %d", cmd.ExitCode())
		errorsMutex.Lock()
		errors = append(errors, err)
		errorsMutex.Unlock()
	}
	wg.Wait()
	w.shellUseTime += time.Since(s)
	if sha256DigestRemote != sha256DigestLocal {
		errors = append(errors, fmt.Errorf("local and remote checksum of file %#v, %s and %s, respectively, do not match", remoteFile, sha256DigestLocal, sha256DigestRemote))
	}
	err = nil
	if len(errors) != 0 {
		err = errors[0]
		for i := 1; i < len(errors); i++ {
			log.Error(errors[i])
		}
	}
	return err
}

func (w *winrsWorker) makeDirectories(remoteFile string, checkIfExists bool) error {
	var command string
	if checkIfExists {
		remoteFileWithSlash := remoteFile + "\\"
		command = fmt.Sprintf(`if not exist "%s" md "%s"`, remoteFileWithSlash, remoteFile)
	} else {
		command = fmt.Sprintf(`md "%s"`, remoteFile)
	}
	return w.RunCommand(command)
}
