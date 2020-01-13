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

func RunCommand(shell *Shell, command string, args []string, winrsConsoleModeStdin, winrsSkipCmdShell bool) error {
	if shell == nil {
		return fmt.Errorf("shell cannot be nil")
	}
	cmd, err := shell.StartCommand(command, args, winrsConsoleModeStdin, winrsSkipCmdShell)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	var errors []error
	var errorsMutex sync.Mutex
	copyFunc := func(dst io.Writer, src io.Reader, name string) {
		_, err = io.Copy(dst, src)
		if err != nil {
			errWrapped := fmt.Errorf("error while copying command's %s to own %s: %w", name, name, err)
			errorsMutex.Lock()
			errors = append(errors, errWrapped)
			errorsMutex.Unlock()
		}
		wg.Done()
	}
	go copyFunc(os.Stderr, cmd.Stderr, "stderr")
	go copyFunc(os.Stdout, cmd.Stdout, "stdout")
	cmd.Wait()
	if cmd.ExitCode() != 0 {
		err := fmt.Errorf("command unexpectedly exited with code %d", cmd.ExitCode())
		errorsMutex.Lock()
		errors = append(errors, err)
		errorsMutex.Unlock()
	}
	wg.Wait()
	err = nil
	if len(errors) != 0 {
		err = errors[0]
		for i := 1; i < len(errors); i++ {
			log.Error(errors[i])
		}
	}
	return err
}

// MustRunCommand is a wrapper around RunCommand and panics with the error returned by RunCommand, if any.
func MustRunCommand(shell *Shell, command string, args []string, winrsConsoleModeStdin, winrsSkipCmdShell bool) {
	err := RunCommand(shell, command, args, winrsConsoleModeStdin, winrsSkipCmdShell)
	if err != nil {
		panic(fmt.Errorf("error while running command %+v: %v", append([]string{command}, args...), err))
	}
}
