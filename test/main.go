package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/jbrekelmans/winrm"
	log "github.com/sirupsen/logrus"
)

const defaultParallelism = 1

func main() {
	hostFlag := flag.String("host", "", "")
	portFlag := flag.String("port", "5986", "")
	userFlag := flag.String("user", "", "")
	passwordFlag := flag.String("password", "", "")
	parallelismFlag := flag.String("parallelism", strconv.Itoa(defaultParallelism), "")
	flag.Parse()
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	port, err := strconv.Atoi(*portFlag)
	if err != nil {
		log.Fatalf("error parsing port: %v", err)
	}
	shellCount, err := strconv.Atoi(*parallelismFlag)
	if err != nil {
		log.Fatalf("error parsing parallelism: %v", err)
	}
	if shellCount < 1 {
		shellCount = 1
	}
	useTLS := true
	maxEnvelopeSize := 500 * 1000
	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxConnsPerHost: 300,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	c, err := winrm.NewClient(context.Background(), useTLS, *hostFlag, port, *userFlag, *passwordFlag, httpClient, &maxEnvelopeSize)
	if err != nil {
		log.Fatalf("error while initializing winrm client: %v", err)
	}
	shells := make([]*winrm.Shell, shellCount)
	for i := 0; i < shellCount; i++ {
		var err1 error
		shells[i], err1 = c.CreateShell()
		if err1 != nil {
			for j := i; j > 0; j-- {
				err2 := shells[j].Close()
				if err2 != nil {
					log.WithFields(log.Fields{
						log.ErrorKey:          err2.Error(),
						winrm.LogFieldShellID: shells[j].ID(),
					}).Errorf("error while closing shell")
				}
			}
			log.WithFields(log.Fields{
				log.ErrorKey: err1.Error(),
			}).Fatalf("error while creating remote shell", err1)
		}
	}
	defer func() {
		for _, shell := range shells {
			err := shell.Close()
			if err != nil {
				log.WithFields(log.Fields{
					log.ErrorKey:          err.Error(),
					winrm.LogFieldShellID: shell.ID(),
				}).Errorf("error while closing shell")
			}
		}
	}()
	localRoot := "."
	remoteRoot := "C:\\workspace"
	winrm.MustRunCommand(shells[0], `winrm get winrm/config`, nil, true, false)
	winrm.MustRunCommand(shells[0], fmt.Sprintf(`if exist "%s" rd /s /q "%s"`, remoteRoot+"\\", remoteRoot), nil, true, false)
	copier, err := winrm.NewFileTreeCopier(shells, remoteRoot, localRoot)
	if err != nil {
		log.Fatalf("error creating copier: %v", err)
	}
	err = copier.Run()
	if err != nil {
		log.Fatalf("error while copying file tree: %v", err)
	}
	winrm.MustRunCommand(shells[0], fmt.Sprintf(`dir "%s"`, remoteRoot), nil, true, false)
	winrm.MustRunCommand(shells[0], fmt.Sprintf(`type "%s"`, remoteRoot+"\\README.md"), nil, true, false)
}
