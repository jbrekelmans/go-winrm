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

func CommandToRunPowershellCode(code string) string {
	var codeUTF16LE bytes.Buffer
	for _, rune := range code {
		r1, r2 := utf16.EncodeRune(rune)
		if r2 == unicode.ReplacementChar {
			if rune > unicode.MaxRune {
				panic("invalid powershell code is not valid UTF-8s")
			}
			var codeUnit [2]byte
			binary.LittleEndian.PutUint16(codeUnit[:], uint16(rune))
			_, _ = codeUTF16LE.Write(codeUnit[:])
		} else {
			var codePoint [4]byte
			codeUTF16LE.Grow(4)
			binary.LittleEndian.PutUint16(codePoint[0:2], uint16(r1))
			binary.LittleEndian.PutUint16(codePoint[2:4], uint16(r2))
			_, _ = codeUTF16LE.Write(codePoint[:])
		}
	}
	codeEncoded := base64.StdEncoding.EncodeToString(codeUTF16LE.Bytes())
	commandEncoded := fmt.Sprintf("powershell.exe -NonInteractive -EncodedCommand %s", codeEncoded)
	return commandEncoded
}

// RunCommand runs the specified cmd.exe command on the remote Shell shell, without sending it input, and streams back stdout
// and stderr to os.Stdout and os.Stderr, respectively.
func RunCommand(shell *Shell, commandAndArgs []string) error {
	cmd, err := shell.Execute(commandAndArgs[0], commandAndArgs[1:]...)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	copyFunc := func(dst io.Writer, src io.Reader) {
		wg.Done()
		_, err := io.Copy(dst, src)
		if err != nil {
			log.Errorf("unexpected error while copying command output to stdout/stderr: %v", err)
		}
	}
	go copyFunc(os.Stdout, cmd.Stdout)
	go copyFunc(os.Stderr, cmd.Stderr)
	cmd.Wait()
	wg.Wait()
	if cmd.ExitCode() != 0 {
		return fmt.Errorf("command unexpectedly exited with status %d", cmd.ExitCode())
	}
	return nil
}

// MustRunCommand is a wrapper around RunCommand and panics with the error returned by RunCommand, if any.
func MustRunCommand(shell *Shell, commandAndArgs []string) {
	err := RunCommand(shell, commandAndArgs)
	if err != nil {
		panic(fmt.Errorf("error while running command %+v: %v", commandAndArgs, err))
	}
}
