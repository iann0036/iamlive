package iamlive

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"syscall"

	"github.com/mitchellh/go-homedir"
)

func setConfigKey(filename, section, line string, unset bool) error {
	fileinfo, err := os.Stat(filename)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(filename, os.O_RDONLY, fileinfo.Mode().Perm())
	if err != nil {
		return err
	}
	defer file.Close()

	var newLines []string
	isCorrectSection := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		scannedLine := scanner.Text()
		if scannedLine != line || !unset || !isCorrectSection { // write all but lines to be removed
			newLines = append(newLines, scannedLine)
		}
		if scannedLine == fmt.Sprintf("[%s]", section) {
			isCorrectSection = true
			if !unset {
				newLines = append(newLines, line)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	file.Close()

	file, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, fileinfo.Mode().Perm())
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range newLines {
		fmt.Fprintln(writer, line)
	}
	return writer.Flush()
}

func setINIConfigAndFileFlush() {
	// set ini
	if *setiniFlag {
		cfgfile, err := homedir.Expand("~/.aws/config")
		if err != nil {
			log.Fatal(err)
		}

		if *profileFlag == "default" {
			if *modeFlag == "csm" {
				err = setConfigKey(cfgfile, "default", "csm_enabled = true", false)
			} else if *modeFlag == "proxy" {
				caBundlePath, err := homedir.Expand(*caBundleFlag)
				if err != nil {
					log.Fatal(err)
				}
				err = setConfigKey(cfgfile, "default", fmt.Sprintf("ca_bundle = %s", caBundlePath), false)
			}
		} else {
			if *modeFlag == "csm" {
				err = setConfigKey(cfgfile, fmt.Sprintf("profile %s", *profileFlag), "csm_enabled = true", false)
			} else if *modeFlag == "proxy" {
				caBundlePath, err := homedir.Expand(*caBundleFlag)
				if err != nil {
					log.Fatal(err)
				}
				err = setConfigKey(cfgfile, fmt.Sprintf("profile %s", *profileFlag), fmt.Sprintf("ca_bundle = %s", caBundlePath), false)
			}
		}

		if err != nil {
			log.Fatal(err)
		}
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
				if *setiniFlag {
					// revert ini
					cfgfile, err := homedir.Expand("~/.aws/config") // need to redeclare
					if err != nil {
						os.Exit(1)
					}

					if *profileFlag == "default" {
						if *modeFlag == "csm" {
							setConfigKey(cfgfile, "default", "csm_enabled = true", true)
						} else if *modeFlag == "proxy" {
							caBundlePath, _ := homedir.Expand(*caBundleFlag)
							setConfigKey(cfgfile, "default", fmt.Sprintf("ca_bundle = %s", caBundlePath), true)
						}
					} else {
						if *modeFlag == "csm" {
							setConfigKey(cfgfile, fmt.Sprintf("profile %s", *profileFlag), "csm_enabled = true", true)
						} else if *modeFlag == "proxy" {
							caBundlePath, _ := homedir.Expand(*caBundleFlag)
							setConfigKey(cfgfile, fmt.Sprintf("profile %s", *profileFlag), fmt.Sprintf("ca_bundle = %s", caBundlePath), true)
						}
					}
				}

				pprof.StopCPUProfile()

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
