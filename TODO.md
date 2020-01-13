# TODO
1. fix deadlock bug where both shell copiers and dirscanners are waiting for each other
1. performance increase opportunities:
    1. measure utilization of commands strings so that performance of command batching can be investigated
    1. allowing sending of commands before receiving response: handle responses on separate goroutines
    1. add throttling in the form of maximum number of requests...
    1. this requires a new abstraction (WinrmHighThroughputConnection)
    1. use compression
    1. upload single file in parallel
      1. use emperical evidence to determine how a file can best be broken up (overhead versus gain) 

1. measure file copy rate
1. measure time it takes until all directories are created (to possibly optimize bootstrapping)

1. make fileCopier support non-relative localRoot argument (e.g. make the root of the tree to copy configurable, so that users can control the structure of the directory that is created)
1. measure average shell utilization (across all workers)
