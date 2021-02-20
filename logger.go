package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/buger/goterm"
)

//go:embed map.json
var bIAMMap []byte

//go:embed iam_definition.json
var bIAMSAR []byte

var callLog []Entry

// Entry is a single CSM entry
type Entry struct {
	Type                string `json:"Type"`
	Service             string `json:"Service"`
	Method              string `json:"Api"`
	Parameters          map[string][]string
	FinalHTTPStatusCode int `json:"FinalHttpStatusCode"`
}

// Statement is a single statement within an IAM policy
type Statement struct {
	Effect   string      `json:"Effect"`
	Action   []string    `json:"Action"`
	Resource interface{} `json:"Resource"`
}

// IAMPolicy is a full IAM policy
type IAMPolicy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

func getPolicyDocument() []byte {
	policy := IAMPolicy{
		Version:   "2012-10-17",
		Statement: []Statement{},
	}

	var actions []string
	var resources []string

	for _, entry := range callLog {
		if *failsonlyFlag && (entry.FinalHTTPStatusCode >= 200 && entry.FinalHTTPStatusCode <= 299) {
			continue
		}

		newActions := getDependantActions(getActions(entry.Service, entry.Method))

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

		resources = []string{"*"}

		if len(entry.Parameters) > 0 {
			resources = getResourcesForCall(entry)
		}
	}

	if *sortAlphabeticalFlag {
		sort.Strings(actions)
	}

	if len(resources) == 1 && resources[0] == "*" {
		policy.Statement = append(policy.Statement, Statement{
			Effect:   "Allow",
			Resource: "*",
			Action:   actions,
		})
	} else {
		policy.Statement = append(policy.Statement, Statement{
			Effect:   "Allow",
			Resource: resources,
			Action:   actions,
		})
	}

	doc, err := json.MarshalIndent(policy, "", "    ")
	if err != nil {
		panic(err)
	}
	return doc
}

func handleLoggedCall() {
	// when making many calls in parallel, the terminal can be glitchy
	// if we flush too often, optional flush on timer
	if *terminalRefreshSecsFlag == 0 {
		writePolicyToTerminal()
	}
}

func writePolicyToTerminal() {
	if len(callLog) == 0 {
		return
	}

	policyDoc := getPolicyDocument()

	goterm.Clear()
	goterm.MoveCursor(1, 1)
	goterm.Println(string(policyDoc))
	goterm.Flush()
}

type iamMapBase struct {
	SDKMethodIAMMappings     map[string][]interface{} `json:"sdk_method_iam_mappings"`
	SDKServiceMappings       map[string]string        `json:"sdk_service_mappings"`
	SDKPermissionlessActions []string                 `json:"sdk_permissionless_actions"`
}

type mappingInfoItem struct {
	Action string `json:"action"`
}

type iamDefService struct {
	Prefix     string            `json:"prefix"`
	Privileges []iamDefPrivilege `json:"privileges"`
}

type iamDefPrivilege struct {
	Privilege     string               `json:"privilege"`
	ResourceTypes []iamDefResourceType `json:"resource_types"`
}

type iamDefResourceType struct {
	DependentActions []string `json:"dependent_actions"`
}

func uniqueSlice(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func getDependantActions(actions []string) []string {
	var iamDef []iamDefService

	err := json.Unmarshal(bIAMSAR, &iamDef)
	if err != nil {
		panic(err)
	}

	for _, baseaction := range actions {
		splitbase := strings.Split(baseaction, ":")
		if len(splitbase) != 2 {
			continue
		}
		baseservice := splitbase[0]
		basemethod := splitbase[1]

		for _, service := range iamDef {
			if strings.ToLower(service.Prefix) == strings.ToLower(baseservice) {
				for _, priv := range service.Privileges {
					if strings.ToLower(priv.Privilege) == strings.ToLower(basemethod) {
						for _, resourceType := range priv.ResourceTypes {
							for _, dependentAction := range resourceType.DependentActions {
								actions = append(actions, dependentAction)
							}
						}
					}
				}
			}
		}
	}

	return uniqueSlice(actions)
}

func getActions(service, method string) []string {
	var iamMap iamMapBase
	var actions []string

	err := json.Unmarshal(bIAMMap, &iamMap)
	if err != nil {
		panic(err)
	}

	// checked if permissionless
	for _, permissionlessAction := range iamMap.SDKPermissionlessActions {
		if strings.ToLower(permissionlessAction) == fmt.Sprintf("%s.%s", strings.ToLower(service), strings.ToLower(method)) {
			return []string{}
		}
	}

	// check IAM mappings
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

	// substitute service name
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

func setTerminalRefresh() {
	if *terminalRefreshSecsFlag <= 0 {
		*terminalRefreshSecsFlag = 1
	}

	ticker := time.NewTicker(time.Duration(*terminalRefreshSecsFlag) * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				writePolicyToTerminal()
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
}

func getResourcesForCall(call Entry) (resources []string) {
	return []string{"*"}
}
