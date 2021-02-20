package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
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
	Region              string `json:"Region"`
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

	if *modeFlag == "csm" {
		var actions []string

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
		}

		if *sortAlphabeticalFlag {
			sort.Strings(actions)
		}

		policy.Statement = append(policy.Statement, Statement{
			Effect:   "Allow",
			Resource: "*",
			Action:   actions,
		})
	} else if *modeFlag == "proxy" {
		for _, entry := range callLog {
			if *failsonlyFlag && (entry.FinalHTTPStatusCode >= 200 && entry.FinalHTTPStatusCode <= 299) {
				continue
			}

			actions := getDependantActions(getActions(entry.Service, entry.Method))
			if *sortAlphabeticalFlag {
				sort.Strings(actions)
			}

			resources := getResourcesForCall(entry)

			policy.Statement = append(policy.Statement, Statement{
				Effect:   "Allow",
				Resource: resources,
				Action:   actions,
			})
		}
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

func countRune(s string, r rune) int {
	count := 0
	for _, c := range s {
		if c == r {
			count++
		}
	}
	return count
}

func writePolicyToTerminal() {
	if len(callLog) == 0 {
		return
	}

	policyDoc := string(getPolicyDocument())
	policyHeight := countRune(policyDoc, '\n') + 1

	goterm.Clear()
	goterm.MoveCursor(1, 1)
	if goterm.Height() < policyHeight {
		fmt.Println(policyDoc)
	} else {
		goterm.Println(policyDoc)
		goterm.Flush()
	}
}

type iamMapMethod struct {
	Action           string                      `json:"action"`
	ResourceMappings map[string]iamMapResMapItem `json:"resource_mappings"`
}

type iamMapResMapItem struct {
	Template string `json:"template"`
}

type iamMapBase struct {
	SDKMethodIAMMappings     map[string][]iamMapMethod `json:"sdk_method_iam_mappings"`
	SDKServiceMappings       map[string]string         `json:"sdk_service_mappings"`
	SDKPermissionlessActions []string                  `json:"sdk_permissionless_actions"`
}

type mappingInfoItem struct {
	Action string `json:"action"`
}

type iamDefService struct {
	Prefix     string            `json:"prefix"`
	Privileges []iamDefPrivilege `json:"privileges"`
	Resources  []iamDefResource  `json:"resources"`
}

type iamDefPrivilege struct {
	Privilege     string               `json:"privilege"`
	ResourceTypes []iamDefResourceType `json:"resource_types"`
	Description   string               `json:"description"`
}

type iamDefResource struct {
	Resource string `json:"resource"`
	Arn      string `json:"arn"`
}

type iamDefResourceType struct {
	DependentActions []string `json:"dependent_actions"`
	ResourceType     string   `json:"resource_type"`
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
				actions = append(actions, item.Action)
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

type resourceType struct {
	ResourceType string `json:"resourceType"`
}

func getResourcesForCall(call Entry) (resources []string) {
	var iamDef []iamDefService

	err := json.Unmarshal(bIAMSAR, &iamDef)
	if err != nil {
		panic(err)
	}

	for _, service := range iamDef {
		if service.Prefix == strings.ToLower(call.Service) {
			privilegearray := mapCallToPrivilegeArray(service, call)

			for _, privilege := range privilegearray {
				for _, resourceType := range privilege.ResourceTypes {
					for _, resource := range service.Resources {
						if resource.Resource == strings.Replace(resourceType.ResourceType, "*", "", -1) && resource.Resource != "" {
							subbedArns := subSARARN(resource.Arn, call)
							for _, subbedArn := range subbedArns {
								if resourceType.ResourceType[len(resourceType.ResourceType)-1:] == "*" || subbedArn[len(subbedArn)-1:] != "*" {
									resources = append(resources, subbedArn)
								}
							}
						}
					}
				}
			}
		}
	}

	if len(resources) == 0 {
		resources = []string{"*"}
	}

	return resources
}

func mapCallToPrivilegeArray(service iamDefService, call Entry) []iamDefPrivilege {
	lowerPriv := fmt.Sprintf("%s:%s", strings.ToLower(call.Service), strings.ToLower(call.Method))

	var privileges []iamDefPrivilege

	var iamMap iamMapBase
	err := json.Unmarshal(bIAMMap, &iamMap)
	if err != nil {
		log.Fatal(err)
	}

	for iamMapMethodName, iamMapMethods := range iamMap.SDKMethodIAMMappings {
		if strings.ToLower(iamMapMethodName) == lowerPriv {
			for _, mappedPriv := range iamMapMethods {
				for _, privilege := range service.Privileges {
					if fmt.Sprintf("%s:%s", strings.ToLower(mapServicePrefix(service.Prefix, iamMap)), strings.ToLower(privilege.Privilege)) == strings.ToLower(mappedPriv.Action) {
						privileges = append(privileges, privilege)
						break
					}
				}
			}
		}
	}

	if len(privileges) == 0 {
		for _, servicePrivilege := range service.Privileges {
			if strings.ToLower(call.Method) == strings.ToLower(servicePrivilege.Privilege) {
				return []iamDefPrivilege{servicePrivilege}
			}
		}
	}

	return []iamDefPrivilege{}
}

func subSARARN(arn string, call Entry) []string {
	var iamMap iamMapBase

	err := json.Unmarshal(bIAMMap, &iamMap)
	if err != nil {
		panic(err)
	}

	for sdkCall, mappingInfo := range iamMap.SDKMethodIAMMappings {
		if fmt.Sprintf("%s.%s", strings.ToLower(call.Service), strings.ToLower(call.Method)) == strings.ToLower(sdkCall) {
			for _, item := range mappingInfo {
				for resMappingVar, resMapping := range item.ResourceMappings {
					if !strings.Contains(resMapping.Template, "%") { // TODO: Handle specials
						arn = regexp.MustCompile(`\$\{`+resMappingVar+`\}`).ReplaceAllString(arn, strings.ReplaceAll(resMapping.Template, `$`, `$$`))
					}
				}
			}
		}
	}

	arns := []string{arn} // matrix
	for paramVarName, params := range call.Parameters {
		newArns := []string{}
		for _, param := range params {
			for i := range arns {
				arn = regexp.MustCompile(`\$\{`+paramVarName+`\}`).ReplaceAllString(arns[i], param) // TODO: Check replace actually happened

				newArns = append(newArns, arn)
			}
		}
		arns = newArns
	}

	retArns := make([]string, 0)
	for _, arn := range arns {
		account := "123456789012"
		partition := "aws"
		if call.Region[0:3] == "cn-" {
			partition = "aws-cn"
		}
		if call.Region[0:7] == "us-gov-" {
			partition = "aws-us-gov"
		}
		arn = regexp.MustCompile(`\$\{Partition\}`).ReplaceAllString(arn, partition)
		arn = regexp.MustCompile(`\$\{Region\}`).ReplaceAllString(arn, call.Region)
		arn = regexp.MustCompile(`\$\{Account\}`).ReplaceAllString(arn, account)
		arn = regexp.MustCompile(`\$\{.+?\}`).ReplaceAllString(arn, "*")

		retArns = append(retArns, arn)
	}

	return retArns
}

func mapServicePrefix(prefix string, mappings iamMapBase) string {
	for sdkprefix, mappedprefix := range mappings.SDKServiceMappings {
		if sdkprefix == prefix {
			return mappedprefix
		}
	}

	return prefix
}
