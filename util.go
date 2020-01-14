package winrm

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"unicode"
	"unicode/utf16"

	log "github.com/sirupsen/logrus"
)

// FormatPowershellScriptCommandLine returns the command and arguments to run the specified PowerShell script.
// The returned slice contains the following elements:
// PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand <base64>
func FormatPowershellScriptCommandLine(script string) []string {
	var scriptUTF16LE bytes.Buffer
	for _, rune := range script {
		r1, r2 := utf16.EncodeRune(rune)
		if r2 == unicode.ReplacementChar {
			if rune > unicode.MaxRune {
				panic("script is not valid UTF-8")
			}
			var codeUnit [2]byte
			binary.LittleEndian.PutUint16(codeUnit[:], uint16(rune))
			_, _ = scriptUTF16LE.Write(codeUnit[:])
		} else {
			var codePoint [4]byte
			scriptUTF16LE.Grow(4)
			binary.LittleEndian.PutUint16(codePoint[0:2], uint16(r1))
			binary.LittleEndian.PutUint16(codePoint[2:4], uint16(r2))
			_, _ = scriptUTF16LE.Write(codePoint[:])
		}
	}
	scriptEncoded := base64.StdEncoding.EncodeToString(scriptUTF16LE.Bytes())
	return []string{
		"PowerShell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Unrestricted", "-EncodedCommand", scriptEncoded,
	}
}

// RunCommand is a safe utility that runs a command on the supplied shell. It copies the remote command's stderr and stdout to os.Stderr
// and os.Stdout, respectively. It also waits for the command to complete and then signals the command in case it does not terminate by
// itself, to avoid leaking resources. Use (*Shell).StartCommand for a lower level alternative.
// winrsConsoleModeStdin and winrsSkipCmdShell correspond to the SOAP options WINRS_CONSOLEMODE_STDIN and WINRS_SKIP_CMD_SHELL, respectively,
// and are defined here: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/c793e333-c409-43c6-a2eb-6ae2489c7ef4
func RunCommand(shell *Shell, command string, args []string, winrsConsoleModeStdin, winrsSkipCmdShell bool) error {
	if shell == nil {
		return fmt.Errorf("shell cannot be nil")
	}
	cmd, err := shell.StartCommand(command, args, winrsConsoleModeStdin, winrsSkipCmdShell)
	if err != nil {
		return err
	}
	defer cmd.Signal()
	var wg sync.WaitGroup
	wg.Add(2)
	var firstErr error
	var firstErrMutex sync.Mutex
	addError := func(err error) {
		firstErrMutex.Lock()
		if firstErr == nil {
			firstErr = err
			firstErrMutex.Unlock()
		} else {
			firstErrMutex.Unlock()
			log.Error(err)
		}
	}
	copyFunc := func(dst io.Writer, src io.Reader, name string) {
		defer wg.Done()
		_, err = io.Copy(dst, src)
		if err != nil {
			addError(fmt.Errorf("error while copying command's %s to own %s: %w", name, name, err))
		}
	}
	go copyFunc(os.Stderr, cmd.Stderr, "stderr")
	go copyFunc(os.Stdout, cmd.Stdout, "stdout")
	cmd.Wait()
	if cmd.ExitCode() != 0 {
		addError(fmt.Errorf("command unexpectedly exited with code %d", cmd.ExitCode()))
	}
	wg.Wait()
	return firstErr
}

// MustRunCommand wraps a call to RunCommand. If RunCommand returns an error then MustRunCommand panics.
func MustRunCommand(shell *Shell, command string, args []string, winrsConsoleModeStdin, winrsSkipCmdShell bool) {
	err := RunCommand(shell, command, args, winrsConsoleModeStdin, winrsSkipCmdShell)
	if err != nil {
		panic(fmt.Errorf("error while running command %+v: %v", append([]string{command}, args...), err))
	}
}

func formatBytes(bytes float64) string {
	units := []string{
		"bytes",
		"KiB",
		"MiB",
		"GiB",
	}
	logBase1024 := 0
	for bytes > 1024.0 && logBase1024 < len(units) {
		bytes /= 1024.0
		logBase1024++
	}
	return fmt.Sprintf("%.3f %s", bytes, units[logBase1024])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FormatURL formats the HTTP URL of a WinRM endpoint.
func FormatURL(useTLS bool, host string, port int) string {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d/wsman", scheme, host, port)
}
