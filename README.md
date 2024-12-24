### LocalSend CLI

Simple CLI program that implements LocalSend v2 protocol

#### Quickstart
Scan the local network to find target: `localsend scan`
Send file: `localsend send -f myfile -p xxx.xxx.xxx.xxx`
Receive file: `localsend recv`

#### Command Reference
```
LocalSend CLI

Usage:
  localsend [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  recv        Receive files from localsend instance
  scan        Scan local network for localsend instance
  send        Send files to localsend instance

Flags:
  -h, --help   help for localsend

Use "localsend [command] --help" for more information about a command.

```

`recv` command 
```
Receive files from localsend instance

Usage:
  localsend recv [flags]

Flags:
  -n, --devname string   Device name that is advertising (default "localsend-cli")
  -d, --dir string       Directory for received files (default ".")
  -h, --help             help for recv
      --https            Do https (default true)
```

`send` command
```
Send files to localsend instance

Usage:
  localsend send [flags]

Flags:
  -f, --file string   File/Directory to be sent
  -h, --help          help for send
      --https         Do https (default true)
  -p, --ip string     IP address of remote localsend instance
```

`scan` command

```
Scan local network for localsend instance

Usage:
  localsend scan [flags]

Flags:
  -h, --help          help for scan
  -t, --timeout int   scan duration in seconds (default 2)
```
