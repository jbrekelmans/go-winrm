# TODO

1. measure byte upload rate
1. measure file copy rate
1. measure time it takes until all directories are created (to possibly optimize bootstrapping)
1. measure utilization of commands strings so that performance of command batching can be investigated

1. use variables in generated shell code to reduce command size and squeeze more bytes into chunks.
1. add option to remove command output copying (to save requests/CPU/network time)

1. make fileCopier support non-relative localRoot argument (e.g. make the root of the tree to copy configurable, so that users can control the structure of the directory that is created)
1. measure average shell utilization (across all workers)
