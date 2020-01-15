package winrm

import (
	"bufio"
	"bytes"
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
const logFieldLocalFile = "file"
const logFieldCopyFileWorker = "worker"

var regexpRemoteFileThatDoesNotNeedEscaping = regexp.MustCompile(`^[a-zA-Z0-9]:(?:\\|(?:\\[a-zA-Z0-9-_\. ^&]+)+)$`)
var regexpFileBasenameThatDoesNotNeedEscaping = regexp.MustCompile(`^[a-zA-Z0-9-_\. ^&]+$`)

type copyFileTask struct {
	LocalFile string
}

type stats struct {
	bytesCopied           int64
	bytesTotal            int64
	directoriesCreated    int64
	directoriesTotal      int64
	startTime             time.Time
	lastReportBytesCopied int64
	lastReportTime        time.Time
}

// FileTreeCopier stores the state needed to efficiently copy file trees over the Windows Remote Management (WinRM) protocol.
type FileTreeCopier struct {
	errors        []error
	errorsMutex   sync.Mutex
	localRoot     string
	localRootStat os.FileInfo
	remoteRoot    string
	shells        []*Shell
	// The waitGroup counter is incremented for each copyFileTask that is created.
	waitGroup     sync.WaitGroup
	copyFileTasks chan *copyFileTask
	stats         stats
	// Used to signal the report loop to finish
	done chan struct{}
}

// NewFileTreeCopier creates a new file copier and guards against errorneous input. remoteRoot must be a cleaned absolute Windows file path
// that starts with a drive letter.
// Limitations:
// 1. if localRoot is a regular file then the remote directory to which it would be copied must not contain an entry with a case-insensitive
//    equal name.
// 2. after cleaning localRoot (using filepath.Clean), it should not contain any characters outside the regular expression class [a-zA-Z0-9-_\. ^&],
//    because escaping such file names is not supported.
func NewFileTreeCopier(shells []*Shell, remoteRoot, localRoot string) (*FileTreeCopier, error) {
	f := &FileTreeCopier{
		localRoot:  localRoot,
		remoteRoot: remoteRoot,
		shells:     make([]*Shell, len(shells)),
	}
	if len(shells) < 1 {
		return nil, fmt.Errorf("shells cannot be empty")
	}
	uniqueShells := map[*Shell]struct{}{}
	for i, shell := range shells {
		if shell == nil {
			return nil, fmt.Errorf("shells contains a nil shell")
		}
		if _, ok := uniqueShells[shell]; ok {
			return nil, fmt.Errorf("shells contains duplicate shell objects")
		}
		uniqueShells[shell] = struct{}{}
		f.shells[i] = shell
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
	f.copyFileTasks = make(chan *copyFileTask, len(f.shells)*2)
	f.done = make(chan struct{})
	return f, nil
}

// copyFileWorker is a structure created for each goroutine that copies files. It also stores state used to measure utilization of WinRM Shells.
type copyFileWorker struct {
	id           int
	f            *FileTreeCopier
	shell        *Shell
	shellUseTime time.Duration
}

func newCopyFileWorker(f *FileTreeCopier, id int, shell *Shell) *copyFileWorker {
	return &copyFileWorker{
		id:    id,
		f:     f,
		shell: shell,
	}
}

func (w *copyFileWorker) RunCommand(command string) error {
	log.Tracef(command)
	s := time.Now()
	err := RunCommand(w.shell, command, nil, true, false)
	w.shellUseTime += time.Since(s)
	return err
}

func (w *copyFileWorker) Run() {
	startTime := time.Now()
	for {
		t, ok := <-w.f.copyFileTasks
		if !ok {
			break
		}
		err := w.copyFile(t.LocalFile)
		if err != nil {
			log.WithFields(log.Fields{
				log.ErrorKey:           err.Error(),
				logFieldLocalFile:      t.LocalFile,
				logFieldCopyFileWorker: w.id,
			}).Errorf("copy file failed")
			w.f.addError(err)
		}
	}
	if log.IsLevelEnabled(shellUtilizationLogLevel) {
		elapsedTime := time.Since(startTime)
		elapsedSeconds := elapsedTime.Seconds()
		shellUsePercentage := w.shellUseTime.Seconds() / elapsedSeconds * 100.0
		log.StandardLogger().WithFields(log.Fields{
			logFieldCopyFileWorker: w.id,
		}).Logf(shellUtilizationLogLevel, "goroutine ran for %.2f seconds with a shell utilization of %.2f%%", elapsedSeconds, shellUsePercentage)
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

// Run copies the file tree.
func (f *FileTreeCopier) Run() error {
	f.stats.startTime = time.Now()
	f.stats.lastReportTime = f.stats.startTime
	for i := 1; i < len(f.shells); i++ {
		copyFileWorker := newCopyFileWorker(f, i, f.shells[i])
		go copyFileWorker.Run()
	}
	go f.reportLoop()
	f.scanDirs()
	f.waitGroup.Wait()
	close(f.copyFileTasks)
	// Signal to the goroutine running reportLoop that it can stop.
	f.done <- struct{}{}
	elapsedSeconds := time.Since(f.stats.startTime).Seconds()
	overallBytesPerSecond := float64(f.stats.bytesCopied) / elapsedSeconds
	log.Infof("copied file tree with %d errors in %2f seconds (upload speed = %s/s, total size = %s)", len(f.errors), elapsedSeconds, formatBytes(overallBytesPerSecond), formatBytes(float64(f.stats.bytesTotal)))
	if len(f.errors) == 0 {
		return nil
	}
	return f.errors[0]
}

func (f *FileTreeCopier) scanDirs() {
	maxCommandSize := f.shells[0].MaxSizeOfCommandWithZeroArguments()
	commandBuffer := make([]byte, maxCommandSize)
	commandDirs := int64(0)
	commandLength := 0
	err := godirwalk.Walk(f.localRoot, &godirwalk.Options{
		Callback: func(localFile string, de *godirwalk.Dirent) error {
			if de.IsDir() {
				remoteFile := f.getRemoteFile(localFile)
				if !strings.HasSuffix(remoteFile, "\\") {
					// Do not attempt to create the root directory...
					command := formatMakeDirectoryCommand(remoteFile, localFile == f.localRoot)
					atomic.AddInt64(&f.stats.directoriesTotal, 1)
					if commandLength == 0 {
						commandLength = copy(commandBuffer, command)
						commandDirs++
					} else if len(command)+1+commandLength <= maxCommandSize {
						commandLength += copy(commandBuffer[commandLength:], "&")
						commandLength += copy(commandBuffer[commandLength:], command)
						commandDirs++
					} else {
						err := RunCommand(f.shells[0], string(commandBuffer[:commandLength]), nil, true, false)
						if err != nil {
							return err
						}
						atomic.AddInt64(&f.stats.directoriesCreated, commandDirs)
						commandLength = copy(commandBuffer, command)
						commandDirs = 1
					}
				}
			} else if de.IsRegular() {
				if localFile == f.localRoot {
					// Special case, if the root is a regular file, we need to ensure it's containing directory exists.
					remoteFile := f.getRemoteFile(localFile)
					i := strings.LastIndex(remoteFile, "\\")
					// i >= because the root is a file
					j := strings.LastIndex(remoteFile[:i], "\\")
					if j >= 0 {
						atomic.AddInt64(&f.stats.directoriesTotal, 1)
						command := formatMakeDirectoryCommand(remoteFile[:i], true)
						log.Info(localFile)
						log.Info(remoteFile)
						log.Info(command)
						commandLength = copy(commandBuffer, command)
						commandDirs++
					} else {
						// remoteFile[:i] is the root directory, so we do not need to check if it exists
					}
				}
				stat, err := os.Lstat(localFile)
				if err != nil {
					return err
				}
				atomic.AddInt64(&f.stats.bytesTotal, stat.Size())
			}
			return nil
		},
		AllowNonDirectory:   true,
		FollowSymbolicLinks: false,
		Unsorted:            true,
	})
	if err != nil {
		f.addError(err)
		return
	}
	if commandLength > 0 {
		err := RunCommand(f.shells[0], string(commandBuffer[:commandLength]), nil, true, false)
		if err != nil {
			f.addError(err)
			return
		}
		atomic.AddInt64(&f.stats.directoriesCreated, commandDirs)
		commandLength = 0
		commandDirs = 0
	}
	// We are done with f.shells[0], use it for copying files.
	copyFileWorker := newCopyFileWorker(f, 0, f.shells[0])
	go copyFileWorker.Run()
	err = godirwalk.Walk(f.localRoot, &godirwalk.Options{
		Callback: func(localFile string, de *godirwalk.Dirent) error {
			if de.IsRegular() {
				f.waitGroup.Add(1)
				f.copyFileTasks <- &copyFileTask{
					LocalFile: localFile,
				}
			}
			return nil
		},
		AllowNonDirectory:   true,
		FollowSymbolicLinks: false,
		Unsorted:            true,
	})
	if err != nil {
		f.addError(err)
	}
}

func (f *FileTreeCopier) reportLoop() {
outer:
	for {
		select {
		case <-f.done:
			break outer
		case now := <-time.After(time.Second * 5):
			bytesCopied := atomic.LoadInt64(&f.stats.bytesCopied)
			bytesCopiedChange := bytesCopied - f.stats.lastReportBytesCopied
			elapsedTime := now.Sub(f.stats.lastReportTime)
			f.stats.lastReportBytesCopied = bytesCopied
			f.stats.lastReportTime = now
			bytesCopiedPerSecond := float64(bytesCopiedChange) / elapsedTime.Seconds()
			progress := float64(bytesCopied) / float64(atomic.LoadInt64(&f.stats.bytesTotal)) * 100.0
			log.Infof("stats: upload speed = %s/s, progress = %.1f%%, dirs = %d/%d",
				formatBytes(bytesCopiedPerSecond),
				progress,
				atomic.LoadInt64(&f.stats.directoriesCreated),
				atomic.LoadInt64(&f.stats.directoriesTotal),
			)
		}
	}
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

func (w *copyFileWorker) copyFile(localFile string) error {
	defer w.f.waitGroup.Done()
	remoteFile := w.f.getRemoteFile(localFile)
	commandAndArgs := FormatPowerShellScriptCommandLine(`begin {
	$path = ` + PowerShellSingleQuotedStringLiteral(remoteFile) + `
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
	stat, err := os.Lstat(localFile)
	if err != nil {
		return err
	}
	sha256DigestLocalObj := sha256.New()
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
	commandStartTime := time.Now()
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
			_, _ = sha256DigestLocalObj.Write(buffer)
			if bytesCopied >= fileSize {
				ended = true
				sha256DigestLocal = hex.EncodeToString(sha256DigestLocalObj.Sum(nil))
			}
			err := cmd.SendInput(base64LineBuffer, ended)
			atomic.AddInt64(&w.f.stats.bytesCopied, int64(bufferLength))
			bufferLength = 0
			if err != nil {
				w.f.addError(err)
			}
		}
	}
	_ = fd.Close()
	fdClosed = true
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		cmd.Signal()
		return err
	}
	if !ended {
		_, _ = sha256DigestLocalObj.Write(buffer[:bufferLength])
		sha256DigestLocal = hex.EncodeToString(sha256DigestLocalObj.Sum(nil))
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
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	gotError := int64(0)
	go func() {
		defer wg.Done()
		_, err = io.Copy(&stderr, cmd.Stderr)
		if err != nil {
			log.WithFields(log.Fields{
				logFieldLocalFile:      localFile,
				logFieldCopyFileWorker: w.id,
				log.ErrorKey:           err.Error(),
				LogFieldCommandID:      cmd.ID(),
				"stderr":               stderr.String(),
			}).Errorf("error while buffering stderr")
			stderr.Reset()
			atomic.StoreInt64(&gotError, 1)
		}
	}()
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(cmd.Stdout)
		for scanner.Scan() {
			var output struct {
				Sha256 string `json:"sha256"`
			}
			if json.Unmarshal(scanner.Bytes(), &output) == nil {
				sha256DigestRemote = output.Sha256
			} else {
				_, _ = stdout.Write(scanner.Bytes())
				_, _ = stdout.WriteString("\n")
			}
		}
		if err := scanner.Err(); err != nil {
			log.WithFields(log.Fields{
				logFieldLocalFile:      localFile,
				logFieldCopyFileWorker: w.id,
				log.ErrorKey:           err.Error(),
				LogFieldCommandID:      cmd.ID(),
				"stdout":               stdout.String(),
			}).Errorf("error while buffering stdout")
			stdout.Reset()
			atomic.StoreInt64(&gotError, 1)
		}
	}()
	cmd.Wait()
	if cmd.ExitCode() != 0 {
		log.WithFields(log.Fields{
			logFieldLocalFile:      localFile,
			logFieldCopyFileWorker: w.id,
			log.ErrorKey:           err.Error(),
			LogFieldCommandID:      cmd.ID(),
		}).Errorf("command exited with non-zero code %d", cmd.ExitCode())
		atomic.StoreInt64(&gotError, 1)
	}
	wg.Wait()
	w.shellUseTime += time.Since(commandStartTime)
	if cmd.ExitCode() == 0 {
		if sha256DigestRemote == "" {
			log.WithFields(log.Fields{
				logFieldLocalFile:      localFile,
				logFieldCopyFileWorker: w.id,
				LogFieldCommandID:      cmd.ID(),
			}).Errorf("copy file command did not output the expected JSON to stdout but exited with code 0")
			gotError = 1
		} else if sha256DigestRemote != sha256DigestLocal {
			log.WithFields(log.Fields{
				logFieldLocalFile:      localFile,
				logFieldCopyFileWorker: w.id,
				LogFieldCommandID:      cmd.ID(),
			}).Errorf("copy file checksum mismatch (local = %s, remote = %s)", sha256DigestLocal, sha256DigestRemote)
			gotError = 1
		}
	}
	if gotError == 0 {
		return nil
	}
	log.WithFields(log.Fields{
		logFieldLocalFile:      localFile,
		logFieldCopyFileWorker: w.id,
		LogFieldCommandID:      cmd.ID(),
		"stdout":               stdout.String(),
		"stderr":               stderr.String(),
	}).Errorf("copy file command failed")
	return fmt.Errorf("got errors while copying file (see logs)")
}

func formatMakeDirectoryCommand(remoteFile string, checkIfExists bool) string {
	var command string
	if checkIfExists {
		remoteFileWithSlash := remoteFile + "\\"
		command = fmt.Sprintf(`if not exist "%s" md "%s"`, remoteFileWithSlash, remoteFile)
	} else {
		command = fmt.Sprintf(`md "%s"`, remoteFile)
	}
	return command
}
