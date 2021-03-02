package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"

	"github.com/mitchellh/go-homedir"
	"gopkg.in/ini.v1"
)

// CLI args
var setiniFlag *bool
var profileFlag *string
var failsonlyFlag *bool
var outputFileFlag *string
var refreshRateFlag *int
var sortAlphabeticalFlag *bool
var hostFlag *string
var modeFlag *string
var bindAddrFlag *string
var caBundleFlag *string
var caKeyFlag *string
var accountIDFlag *string
var cpuProfileFlag = flag.String("cpu-profile", "", "[experimental] write a CPU profile to this file (for performance testing purposes)")

func parseConfig() {
	setIni := false
	profile := "default"
	failsOnly := false
	outputFile := ""
	refreshRate := 0
	sortAlphabetical := false
	host := "127.0.0.1"
	mode := "csm"
	bindAddr := "127.0.0.1:10080"
	caBundle := "~/.iamlive/ca.pem"
	caKey := "~/.iamlive/ca.key"
	accountID := "123456789012"

	cfgfile, err := homedir.Expand("~/.iamlive/config")
	if err == nil {
		cfg, err := ini.Load(cfgfile)
		if err == nil {
			if cfg.Section("").HasKey("set-ini") {
				setIni, _ = cfg.Section("").Key("set-ini").Bool()
			}
			if cfg.Section("").HasKey("profile") {
				profile = cfg.Section("").Key("profile").String()
			}
			if cfg.Section("").HasKey("fails-only") {
				failsOnly, _ = cfg.Section("").Key("fails-only").Bool()
			}
			if cfg.Section("").HasKey("output-file") {
				outputFile = cfg.Section("").Key("output-file").String()
			}
			if cfg.Section("").HasKey("refresh-rate") {
				refreshRate, _ = cfg.Section("").Key("refresh-rate").Int()
			}
			if cfg.Section("").HasKey("sort-alphabetical") {
				sortAlphabetical, _ = cfg.Section("").Key("sort-alphabetical").Bool()
			}
			if cfg.Section("").HasKey("host") {
				host = cfg.Section("").Key("host").String()
			}
			if cfg.Section("").HasKey("mode") {
				mode = cfg.Section("").Key("mode").String()
			}
			if cfg.Section("").HasKey("bind-addr") {
				bindAddr = cfg.Section("").Key("bind-addr").String()
			}
			if cfg.Section("").HasKey("ca-bundle") {
				caBundle = cfg.Section("").Key("ca-bundle").String()
			}
			if cfg.Section("").HasKey("ca-key") {
				caKey = cfg.Section("").Key("ca-key").String()
			}
			if cfg.Section("").HasKey("account-id") {
				accountID = cfg.Section("").Key("account-id").String()
			}
		}
	}

	setiniFlag = flag.Bool("set-ini", setIni, "when set, the .aws/config file will be updated to use the CSM monitoring or CA bundle and removed when exiting")
	profileFlag = flag.String("profile", profile, "use the specified profile when combined with --set-ini")
	failsonlyFlag = flag.Bool("fails-only", failsOnly, "when set, only failed AWS calls will be added to the policy, csm mode only")
	outputFileFlag = flag.String("output-file", outputFile, "specify a file that will be written to on SIGHUP or exit")
	refreshRateFlag = flag.Int("refresh-rate", refreshRate, "instead of flushing to console every API call, do it this number of seconds")
	sortAlphabeticalFlag = flag.Bool("sort-alphabetical", sortAlphabetical, "sort actions alphabetically")
	hostFlag = flag.String("host", host, "host to listen on for CSM")
	modeFlag = flag.String("mode", mode, "[experimental] the listening mode (csm,proxy)")
	bindAddrFlag = flag.String("bind-addr", bindAddr, "[experimental] the bind address for proxy mode")
	caBundleFlag = flag.String("ca-bundle", caBundle, "[experimental] the CA certificate bundle (PEM) to use for proxy mode")
	caKeyFlag = flag.String("ca-key", caKey, "[experimental] the CA certificate key to use for proxy mode")
	accountIDFlag = flag.String("account-id", accountID, "[experimental] the AWS account ID to use in policy outputs within proxy mode")
}

func main() {
	parseConfig()

	flag.Parse()

	if *cpuProfileFlag != "" {
		f, err := os.Create(*cpuProfileFlag)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *refreshRateFlag != 0 {
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
