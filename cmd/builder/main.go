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
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	shellCount := 2
	useTLS := true
	maxEnvelopeSize := 500 * 1000
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
	c, err := winrm.NewClient(useTLS, host, port, user, password, httpClient, context.Background(), &maxEnvelopeSize)
	if err != nil {
		log.Fatalf("error while initializing winrm client: %v", err)
	}
	shells := make([]*winrm.Shell, shellCount)
	for i := 0; i < shellCount; i++ {
		var err1 error
		shells[i], err1 = c.CreateShell()
		if err1 != nil {
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
	scanDirWorkers := 2
	localRoot := "scripts/cloud-builders-community/windows-builder"
	remoteRoot := "C:\\workspace2"
	// localRoot := "scripts/cloud-builders-community/windows-builder/scripts/bootstrap.ps1"
	// remoteRoot := "C:\\workspace2\\bootstrap.ps1"
	winrm.MustRunCommand(shells[0], `winrm get winrm/config`, nil, true, false)
	winrm.MustRunCommand(shells[0], fmt.Sprintf(`if exist "%s" rd /s /q "%s"`, remoteRoot+"\\", remoteRoot), nil, true, false)
	copier, err := winrm.NewFileTreeCopier(shells, scanDirWorkers, remoteRoot, localRoot)
	err = copier.Run()
	if err != nil {
		log.Fatalf("error while copying file: %v", err)
	}
	winrm.MustRunCommand(shells[0], fmt.Sprintf(`dir "%s"`, "C:\\workspace2\\scripts\\cloud-builders-community\\windows-builder"), nil, true, false)
	winrm.MustRunCommand(shells[0], fmt.Sprintf(`type "%s"`, "C:\\workspace2\\scripts\\cloud-builders-community\\windows-builder\\README.md"), nil, true, false)
}
