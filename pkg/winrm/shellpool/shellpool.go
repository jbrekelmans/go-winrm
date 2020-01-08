package shellpool

import (
	"github.com/jbrekelmans/go-winrm-fast/pkg/winrm/client"
)

type ShellPool interface {
}

func NewShellPool(client *client.Client) *ShellPool {

	return nil
}
