# GoCave

Finds code caves inside of a PE binary.
This project is a port go of https://github.com/axcheron/pycave which is implemented in python.

## Usage

```
Find code caves in PE files of given length

Usage:
  gocave [flags]

Flags:
  -b, --base uint32   Base address (default 4194304)
  -f, --file string   PE File to analyze
  -h, --help          help for gocave
  -s, --size int      Minimal size of code cave (default 300)

```

## Build

### Linux

```
GOOS=linux GOARCH=386 go build -o gocave.exe ./main.go
```

### Windows >= 7

```
GOOS=windows GOARCH=386 go build -o gocave.exe ./main.go
```

### Windows Vista

In order to build this for older Versions like Vista, golang Version 1.10.x need to be used.

```
GOOS=windows GOARCH=386 go build -o gocave.exe ./main.go
```
