package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mitchellh/go-homedir"
	"gopkg.in/ini.v1"
)

func setCSMConfigAndFileFlush() {
	// set ini
	if *setiniFlag {
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
	}

	// listen for exit, cleanup and flush
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		for s := range sigc {
			// flush to file
			if *outputFileFlag != "" {
				err := ioutil.WriteFile(*outputFileFlag, getPolicyDocument(), 0644)
				if err != nil {
					log.Fatalf("Error writing policy to %s", *outputFileFlag)
				}
			}

			if s == syscall.SIGINT || s == syscall.SIGTERM || s == syscall.SIGQUIT {
				// revert ini
				cfgfile, err := homedir.Expand("~/.aws/config") // need to redeclare
				if err != nil {
					os.Exit(1)
				}

				cfg, err := ini.Load(cfgfile)
				if err != nil {
					os.Exit(1)
				}

				if *setiniFlag {
					if *profileFlag == "default" {
						cfg.Section("default").DeleteKey("csm_enabled")
					} else {
						cfg.Section(fmt.Sprintf("profile %s", *profileFlag)).DeleteKey("csm_enabled")
					}
					cfg.SaveTo(cfgfile)
				}

				// exit
				os.Exit(0)
			}
		}
	}()
}

func listenForEvents() {
	var iamMap iamMapBase

	addr := net.UDPAddr{
		Port: 31000,
		IP:   net.ParseIP(*hostFlag),
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

	err = json.Unmarshal(bIAMMap, &iamMap)
	if err != nil {
		panic(err)
	}

	var buf [1048576]byte
	for {
		rlen, _, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			panic(err)
		}

		entries := strings.Split(string(buf[0:rlen]), "\n")

	EntryLoop:
		for _, entry := range entries {
			var e Entry

			err := json.Unmarshal([]byte(entry), &e)
			if err != nil {
				panic(err)
			}

			// checked if permissionless
			for _, permissionlessAction := range iamMap.SDKPermissionlessActions {
				if strings.ToLower(permissionlessAction) == fmt.Sprintf("%s.%s", strings.ToLower(e.Service), strings.ToLower(e.Method)) {
					continue EntryLoop
				}
			}

			if e.Type == "ApiCall" {
				callLog = append(callLog, e)
				handleLoggedCall()
			}
		}
	}
}
