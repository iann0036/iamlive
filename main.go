package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
)

// CLI args
var setiniFlag = flag.Bool("set-ini", false, "when set, the .aws/config file will be updated to use the CSM monitoring or CA bundle and removed when exiting")
var profileFlag = flag.String("profile", "default", "use the specified profile when combined with --set-ini")
var failsonlyFlag = flag.Bool("fails-only", false, "when set, only failed AWS calls will be added to the policy, csm mode only")
var outputFileFlag = flag.String("output-file", "", "specify a file that will be written to on SIGHUP or exit")
var terminalRefreshSecsFlag = flag.Int("refresh-rate", 0, "instead of flushing to console every API call, do it this number of seconds")
var sortAlphabeticalFlag = flag.Bool("sort-alphabetical", false, "sort actions alphabetically")
var hostFlag = flag.String("host", "127.0.0.1", "host to listen on for CSM")
var modeFlag = flag.String("mode", "csm", "[experimental] the listening mode (csm,proxy)")
var bindAddrFlag = flag.String("bind-addr", "127.0.0.1:10080", "[experimental] the bind address for proxy mode")
var caBundleFlag = flag.String("ca-bundle", "~/.iamlive/ca.pem", "[experimental] the CA certificate bundle (PEM) to use for proxy mode")
var caKeyFlag = flag.String("ca-key", "~/.iamlive/ca.key", "[experimental] the CA certificate key to use for proxy mode")
var accountIDFlag = flag.String("account-id", "123456789012", "[experimental] the AWS account ID to use in policy outputs within proxy mode")
var cpuProfileFlag = flag.String("cpu-profile", "", "[experimental] write a CPU profile to this file (for performance testing purposes)")

func main() {
	flag.Parse()

	if *cpuProfileFlag != "" {
		f, err := os.Create(*cpuProfileFlag)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *terminalRefreshSecsFlag != 0 {
		setTerminalRefresh()
	}

	setINIConfigAndFileFlush()
	loadMaps()

	if *modeFlag == "csm" {
		listenForEvents()
		handleLoggedCall()
	} else if *modeFlag == "proxy" {
		readServiceFiles()
		createProxy(*bindAddrFlag)
	} else {
		fmt.Println("ERROR: unknown mode")
	}
}
