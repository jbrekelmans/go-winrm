package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/jbrekelmans/go-winrm-fast/pkg/winrm"
	log "github.com/sirupsen/logrus"
)

func main() {
	// log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

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
	c, err := winrm.NewClient(useTLS, host, port, user, password, httpClient, context.Background())
	if err != nil {
		log.Fatalf("error while initializing winrm client: %v", err)
	}
	shell, err := c.CreateShell()
	if err != nil {
		log.Fatalf("error while creating remote shell: %v", err)
	}
	defer shell.Close()
	localRoot := "scripts/cloud-builders-community/windows-builder"
	remoteRoot := "C:\\workspace2"
	// winrm.MustRunCommand(shell, []string{`winrm get winrm/config`})
	winrm.MustRunCommand(shell, []string{fmt.Sprintf(`if exist "%s" rd /s /q "%s"`, remoteRoot+"\\", remoteRoot)})
	copier, err := winrm.NewFileTreeCopier(shell, remoteRoot, localRoot)
	err = copier.Run()
	if err != nil {
		log.Fatalf("error while copying file: %v", err)
	}
	winrm.MustRunCommand(shell, []string{fmt.Sprintf(`type "%s"`, "C:\\workspace2\\scripts\\cloud-builders-community\\windows-builder\\README.md")})
}
