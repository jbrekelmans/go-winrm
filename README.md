# Introduction
This package enables clients written in Go to quickly upload files to a Windows server, based on the Windows Remote Management (WinRM) protocol.

The approach to copying files is the same as [Ansible's](https://github.com/ansible/ansible/blob/7092c196ed0f0e1ee9a53d4040d5ff8c509c05b6/lib/ansible/plugins/connection/winrm.py#L586), and a single file tree can be copied in parallel. These two features make this package hundreds of times faster than [github.com/packer-community/winrmcp](https://github.com/packer-community/winrmcp).

To realize the above, this package exposes WinRM functionality useful for PowerShell pipelines, that is not available in [github.com/masterzen/winrm](https://github.com/masterzen/winrm):
1. The command options `WINRS_CONSOLEMODE_STDIN` and `WINRS_SKIP_CMD_SHELL` are exposed. These options are defined [here](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/c793e333-c409-43c6-a2eb-6ae2489c7ef4).
1. The stdin stream of a command can be closed.

It should be noted that [github.com/masterzen/winrm](https://github.com/mas     terzen/winrm) has better documentation than this package, and will probably be better maintained. But we have a simpler way of supporting different authentication methods, by allowing users to set a `*http.Client` rather than [inventing another abstraction](https://github.com/masterzen/winrm/blob/4a130fc515aca28ec62aa873750017eb2094b344/client.go#L25).

## How do I use this package?
See [test/main.go](test/main.go) for example code.

