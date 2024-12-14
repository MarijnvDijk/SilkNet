# SilkNet
SilkNet is a Drakvuf and Sysmon log parser that reports whether an executable follows a behavioral net. SilkNet was designed and created to detect Early Cascade Injection.

## Usage
```
Usage: main.py <Source Type(s)> [Options]

Options:
  -h, --help            show this help message and exit
  -c CONFIG, --config=CONFIG
                        config filename (default: config.json)
  --regenerate-config   regenerate config
  -n NETSDIR, --net-dir=NETSDIR
                        directory where behavioural nets are stored

  Source Types:
    -e, --silketw       enable silketw parsing
    -s, --sysmon        enable sysmon parsing

  Drakvuf:
    --syscall-file=SYSCALL
                        log file containing syscall log
    --sysret-file=SYSRET
                        log file containing sysret log
    --pid=PID           PID of process to inspect
    -i DRAKVUF_ID, --analysis-id=DRAKVUF_ID
                        drakvuf analysis ID

  Sysmon:
    -x SYSMONXML        Sysmon XML File
    --map-pid=RPID      Drakvuf Sample PID as found in Sysmon Logs
```