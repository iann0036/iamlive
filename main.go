package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/buger/goterm"
	"github.com/mitchellh/go-homedir"
	"gopkg.in/ini.v1"
)

//go:embed map.json
var bIAMMap []byte

var callLog []Entry

// CLI args
var setiniFlag = flag.Bool("setini", false, "when set, the .aws/config file will be updated to use the CSM monitoring (and removed when exiting)")
var profileFlag = flag.String("profile", "default", "use the specified profile when combined with --setini")
var failsonlyFlag = flag.Bool("failsonly", false, "when set, only failed AWS calls will be added to the policy")

// Entry is a single CSM entry
type Entry struct {
	Type                string `json:"Type"`
	Service             string `json:"Service"`
	Method              string `json:"Api"`
	FinalHTTPStatusCode int    `json:"FinalHttpStatusCode"`
}

// Statement is a single statement within an IAM policy
type Statement struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource string   `json:"Resource"`
}

// IAMPolicy is a full IAM policy
type IAMPolicy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

func setCSMConfig() {
	cfgfile, err := homedir.Expand("~/.aws/config")
	if err != nil {
		return
	}

	cfg, err := ini.Load(cfgfile)
	if err != nil {
		return
	}

	if *profileFlag == "default" {
		cfg.Section("default").Key("csm_enabled").SetValue("true")
	} else {
		cfg.Section(fmt.Sprintf("profile %s", *profileFlag)).Key("csm_enabled").SetValue("true")
	}

	cfg.SaveTo(cfgfile)

	// listen for exit and cleanup
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		<-sigc
		if *profileFlag == "default" {
			cfg.Section("default").DeleteKey("csm_enabled")
		} else {
			cfg.Section(fmt.Sprintf("profile %s", *profileFlag)).DeleteKey("csm_enabled")
		}
		cfg.SaveTo(cfgfile)

		os.Exit(0)
	}()
}

func listenForEvents() {
	addr := net.UDPAddr{
		Port: 31000,
		IP:   net.ParseIP("127.0.0.1"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		panic(err)
	}
	err = conn.SetReadBuffer(1048576)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	var buf [1048576]byte
	for {
		rlen, _, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			panic(err)
		}

		entries := strings.Split(string(buf[0:rlen]), "\n")

		for _, entry := range entries {
			var e Entry

			err := json.Unmarshal([]byte(entry), &e)
			if err != nil {
				panic(err)
			}

			if e.Type == "ApiCall" {
				callLog = append(callLog, e)
				handleLoggedCall()
			}
		}
	}
}

func handleLoggedCall() {
	policy := IAMPolicy{
		Version:   "2012-10-17",
		Statement: []Statement{},
	}

	var actions []string

	for _, entry := range callLog {
		if *failsonlyFlag && (entry.FinalHTTPStatusCode >= 200 && entry.FinalHTTPStatusCode <= 299) {
			continue
		}

		newActions := getAction(entry.Service, entry.Method)

		for _, newAction := range newActions {
			foundAction := false

			for _, action := range actions {
				if action == newAction {
					foundAction = true
					break
				}
			}

			if !foundAction {
				actions = append(actions, newAction)
			}
		}
	}

	policy.Statement = append(policy.Statement, Statement{
		Effect:   "Allow",
		Resource: "*",
		Action:   actions,
	})

	b, err := json.MarshalIndent(policy, "", "    ")
	if err != nil {
		panic(err)
	}

	goterm.Clear()
	goterm.MoveCursor(1, 1)
	goterm.Println(string(b))
	goterm.Flush()
}

type iamMapBase struct {
	SDKMethodIAMMappings map[string][]interface{} `json:"sdk_method_iam_mappings"`
	SDKServiceMappings   map[string]string        `json:"sdk_service_mappings"`
}

type mappingInfoItem struct {
	Action string `json:"action"`
}

func getAction(service, method string) []string {
	var iamMap iamMapBase
	var actions []string

	err := json.Unmarshal(bIAMMap, &iamMap)
	if err != nil {
		panic(err)
	}

	for sdkCall, mappingInfo := range iamMap.SDKMethodIAMMappings {
		if fmt.Sprintf("%s.%s", strings.ToLower(service), strings.ToLower(method)) == strings.ToLower(sdkCall) {
			for _, item := range mappingInfo {
				for mappingInfoItemKey, mappingInfoItemValue := range item.(map[string]interface{}) {
					if mappingInfoItemKey == "action" {
						actions = append(actions, fmt.Sprintf("%v", mappingInfoItemValue))
					}
				}
			}
		}
	}

	if len(actions) > 0 {
		return actions
	}

	for sdkService, iamService := range iamMap.SDKServiceMappings {
		if service == sdkService {
			service = iamService
			break
		}
	}

	return []string{
		fmt.Sprintf("%s:%s", strings.ToLower(service), method),
	}
}

func main() {
	flag.Parse()

	if *setiniFlag {
		setCSMConfig()
	}
	listenForEvents()
	handleLoggedCall()
}
