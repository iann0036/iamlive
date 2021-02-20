package main

import (
	_ "embed"
	"flag"
	"fmt"
)

// CLI args
var setiniFlag = flag.Bool("set-ini", false, "when set, the .aws/config file will be updated to use the CSM monitoring and removed when exiting")
var profileFlag = flag.String("profile", "default", "use the specified profile when combined with --set-ini")
var failsonlyFlag = flag.Bool("fails-only", false, "when set, only failed AWS calls will be added to the policy")
var outputFileFlag = flag.String("output-file", "", "specify a file that will be written to on SIGHUP or exit")
var terminalRefreshSecsFlag = flag.Int("refresh-rate", 0, "instead of flushing to console every API call, do it this number of seconds")
var sortAlphabeticalFlag = flag.Bool("sort-alphabetical", false, "sort actions alphabetically")
var hostFlag = flag.String("host", "127.0.0.1", "host to listen on")
var modeFlag = flag.String("mode", "csm", "[experimental] the listening mode (csm,proxy)")
var bindAddrFlag = flag.String("bind-addr", "127.0.0.1:10080", "[experimental] the bind address for proxy mode")

func main() {
	flag.Parse()

	if *terminalRefreshSecsFlag != 0 {
		setTerminalRefresh()
	}

	if *modeFlag == "csm" {
		setCSMConfigAndFileFlush()
		listenForEvents()
		handleLoggedCall()
	} else if *modeFlag == "proxy" {
		readServiceFiles()
		createProxy(*bindAddrFlag)
	} else {
		fmt.Println("ERROR: unknown mode")
	}
}
