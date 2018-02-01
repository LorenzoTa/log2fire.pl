log2fire.pl 

The program reads one or more files (--file accepts a glob too), search for valid lines (validated by --regex), split those lines using --pattern_separator and take only the IP at the specified --ip_position. IP are then cleaned from all unnecessary characters like quotes or semicolon. All IP (with the exception of those putted in the --whitelist) are stored in a cache where number of their occurences are stored too.

For each IP exceeding the --max, a pair of jobs are scheduled to run. The first is the block one and is scheduled to run immediatly. The latter is the unblock one and is scheduled to run after --time_of_block, expressed in seconds.
