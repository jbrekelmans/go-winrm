package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"unicode"
	"unicode/utf16"

	"github.com/jbrekelmans/go-winrm-fast/pkg/winrm/client"
	zenwinrm "github.com/masterzen/winrm"
)

func main() {
	useTLS := true
	host := ""
	port := 5986
	user := ""
	password := ""
	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxConnsPerHost: 300,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	c, err := client.NewClient(useTLS, host, port, user, password, httpClient, context.Background())
	if err != nil {
		log.Fatalf("error while initializing winrm client: %v", err)
	}
	shell, err := c.CreateShell()
	if err != nil {
		log.Fatalf("error while creating remote shell: %v", err)
	}
	defer shell.Close()
	err = runCommand(shell, []string{"winrm", "get", "winrm/config"})
	if err != nil {
		log.Fatalf("error while getting winrm config: %v", err)
	}
	err = test(shell)
	if err != nil {
		log.Fatalf("asdf: %v", err)
	}
}

func commandToRunPowershellCode(code string) string {
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

func test(shell *zenwinrm.Shell) error {
	log.Print("testing")
	input := strings.NewReader("blabla\r\nasdf\r\n")
	cmd, err := shell.Execute(commandToRunPowershellCode(`while($true)
	{
		$input = Read-Host
		Write-Host "lol1"
		Write-Host ([string]$input)
		Write-Host "lol2"
		Write-Host ($input.Length)
		if ($input.Length == 0) {
			break
		}
		break
	}
	`))
	if err != nil {
		log.Fatalf("bla error: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(3)
	copyFunc := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		if err != nil {
			log.Printf("unexpected error while copying command output to stdout/stderr: %v", err)
		}
		wg.Done()
	}
	go copyFunc(os.Stdout, cmd.Stdout)
	go copyFunc(os.Stderr, cmd.Stderr)
	go func() {
		_, err := io.Copy(cmd.Stdin, input)
		if err != nil {
			log.Printf("unexpected error while copying input to command stdin: %v", err)
		}
		wg.Done()
	}()
	cmd.Wait()
	wg.Wait()
	return nil
}

func runCommand(shell *zenwinrm.Shell, commandAndArgs []string) error {
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
			log.Printf("unexpected error while copying command output to stdout/stderr: %v", err)
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
