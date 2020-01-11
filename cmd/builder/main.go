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

	shellCount := 2
	useTLS := true
	localRoot := "scripts/cloud-builders-community/windows-builder"
	remoteRoot := "C:\\workspace2"

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
	shells := make([]*winrm.Shell, shellCount)
	for i := 0; i < shellCount; i++ {
		var err1 error
		shells[i], err1 = c.CreateShell()
		if err != nil {
			for i > 0 {
				i--
				err2 := shells[i].Close()
				if err2 != nil {
					log.Errorf("error while closing shell: %v", err2)
				}
			}
			log.Fatalf("error while creating remote shell: %v", err1)
		}
	}
	defer func() {
		for _, shell := range shells {
			err := shell.Close()
			if err != nil {
				log.Errorf("error while closing shell: %v", err)
			}
		}
	}()
	// winrm.MustRunCommand(shells[0], []string{`winrm get winrm/config`})
	winrm.MustRunCommand(shells[0], []string{fmt.Sprintf(`if exist "%s" rd /s /q "%s"`, remoteRoot+"\\", remoteRoot)})
	copier, err := winrm.NewFileTreeCopier(shells, remoteRoot, localRoot)
	err = copier.Run()
	if err != nil {
		log.Fatalf("error while copying file: %v", err)
	}
	winrm.MustRunCommand(shells[0], []string{fmt.Sprintf(`type "%s"`, "C:\\workspace2\\scripts\\cloud-builders-community\\windows-builder\\README.md")})
}
