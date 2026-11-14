// This launcher configures the pinned, unmodified native Dumpling library.
// Secrets are read from a private file, never from process arguments.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/pingcap/tidb/dumpling/export"
	"github.com/spf13/pflag"
)

const revision = "8b857efa20363d50a8fa2ea7dd9809a85a61b115"

type configuration struct {
	Host     string   `json:"host"`
	Port     uint16   `json:"port"`
	User     string   `json:"user"`
	Password string   `json:"password"`
	CA       *string  `json:"ca"`
	Schema   string   `json:"schema"`
	Tables   []string `json:"tables"`
	Output   string   `json:"output"`
	Snapshot string   `json:"snapshot"`
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("fg-dumpling-run 1; native Dumpling v8.5.8 (%s)\n", revision)
		return
	}
	if err := run(); err != nil {
		// Native errors may contain source values or connection facts.
		fmt.Fprintln(os.Stderr, "Native Dumpling capture failed; inspect the private operator diagnostic log")
		os.Exit(1)
	}
}

func run() (runError error) {
	if len(os.Args) != 3 || os.Args[1] != "--config" {
		return errors.New("private configuration required")
	}
	file, err := os.Open(os.Args[2])
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private configuration required")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1024*1024))
	decoder.DisallowUnknownFields()
	var input configuration
	if err = decoder.Decode(&input); err != nil {
		return err
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing configuration")
	}
	if input.Host == "" || input.Port == 0 || input.User == "" || len(input.Tables) == 0 || input.Output == "" || input.Schema == "" {
		return errors.New("incomplete configuration")
	}
	if err = os.MkdirAll(input.Output, 0700); err != nil {
		return err
	}
	outputInfo, err := os.Stat(input.Output)
	if err != nil || !outputInfo.IsDir() || outputInfo.Mode().Perm()&0077 != 0 {
		return errors.New("private output directory required")
	}
	defer func() {
		if runError == nil {
			return
		}
		log, openError := os.OpenFile(filepath.Join(input.Output, "launcher-private.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if openError != nil {
			return
		}
		defer log.Close()
		if log.Chmod(0600) == nil {
			fmt.Fprintln(log, runError.Error())
		}
	}()
	if _, err = strconv.ParseUint(input.Snapshot, 10, 64); err != nil {
		return errors.New("snapshot timestamp required")
	}
	config := export.DefaultConfig()
	flags := pflag.NewFlagSet("native-dumpling", pflag.ContinueOnError)
	flags.SetOutput(io.Discard)
	// The pinned upstream backend parser reads this global flag set even
	// when Config.ParseFromFlags receives another one. No OS argv is parsed.
	pflag.CommandLine = flags
	config.DefineFlags(flags)
	tables := make([]string, 0, len(input.Tables))
	for _, table := range input.Tables {
		tables = append(tables, input.Schema+"."+table)
	}
	values := map[string]string{
		"host": input.Host, "port": strconv.Itoa(int(input.Port)), "user": input.User, "password": input.Password,
		"tables-list": strings.Join(tables, ","), "output": input.Output, "filetype": "sql",
		"no-schemas": "true", "no-views": "true", "no-sequences": "true", "threads": "1",
		"consistency": "snapshot", "snapshot": input.Snapshot, "status-addr": "127.0.0.1:0",
		"params": "time_zone=+00:00", "loglevel": "error", "logfile": input.Output + "/native-private.log",
	}
	if input.CA != nil {
		values["ca"] = *input.CA
	}
	for key, value := range values {
		if err = flags.Set(key, value); err != nil {
			return errors.New("unsupported pinned native setting")
		}
	}
	if err = config.ParseFromFlags(flags); err != nil {
		return err
	}
	context, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dumper, err := export.NewDumper(context, config)
	if err != nil {
		return err
	}
	defer dumper.Close()
	return dumper.Dump()
}
