package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"reflect"
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
			var actions []string

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

			policy.Statement = getStatementsForProxyCall(entry)

		ActionLoop: // add any actions shown in SAR dependant_actions not added by map (is this even possible?)
			for _, action := range actions {
				for _, statement := range policy.Statement {
					for _, statementAction := range statement.Action {
						if statementAction == action {
							continue ActionLoop
						}
					}
				}

				policy.Statement = append(policy.Statement, Statement{
					Effect:   "Allow",
					Resource: []string{"*"},
					Action:   []string{action},
				})
			}
		}

		policy = aggregatePolicy(policy)

		for i := 0; i < len(policy.Statement); i++ { // make any single wildcard resource a non-array
			resource := policy.Statement[i].Resource.([]string)
			if len(resource) == 1 && resource[0] == "*" {
				policy.Statement[i].Resource = "*"
			}
		}
	}

	doc, err := json.MarshalIndent(policy, "", "    ")
	if err != nil {
		panic(err)
	}
	return doc
}

func removeStatementItem(slice []Statement, i int) []Statement {
	copy(slice[i:], slice[i+1:])
	return slice[:len(slice)-1]
}

func aggregatePolicy(policy IAMPolicy) IAMPolicy {
	for i := 0; i < len(policy.Statement); i++ {
		sort.Strings(policy.Statement[i].Resource.([]string))
		for j := i + 1; j < len(policy.Statement); j++ {
			sort.Strings(policy.Statement[j].Resource.([]string))

			if reflect.DeepEqual(policy.Statement[i].Resource.([]string), policy.Statement[j].Resource.([]string)) {
				policy.Statement[i].Action = append(policy.Statement[i].Action, policy.Statement[j].Action...) // combine
				policy.Statement = removeStatementItem(policy.Statement, j)                                    // remove dupe
				j--
			}
		}

		policy.Statement[i].Action = uniqueSlice(policy.Statement[i].Action)
		policy.Statement[i].Resource = uniqueSlice(policy.Statement[i].Resource.([]string))
	}

	return policy
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
		fmt.Println("\n\n" + policyDoc)
	} else {
		goterm.Println(policyDoc)
		goterm.Flush()
	}
}

type iamMapMethod struct {
	Action           string                      `json:"action"`
	ResourceMappings map[string]iamMapResMapItem `json:"resource_mappings"`
	ArnOverride      iamMapArnOverride           `json:"arn_override"`
}

type iamMapArnOverride struct {
	Template string `json:"template"`
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

func resolveSpecials(arn string, call Entry) []string {
	startIndex := strings.Index(arn, "%%")
	endIndex := strings.LastIndex(arn, "%%")

	if startIndex > -1 && endIndex != startIndex {
		parts := strings.Split(arn[startIndex+2:endIndex-1], "%")

		if len(parts) < 2 {
			return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
		}

		switch parts[0] {
		case "iftruthy":
			if len(parts) != 4 {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}

			arns := subARNParameters(parts[1], call, true)
			if len(arns) < 1 {
				return []string{arn[0:startIndex] + parts[3] + arn[endIndex+2:]}
			}
			if arns[0] == "" {
				return []string{arn[0:startIndex] + parts[3] + arn[endIndex+2:]}
			}

			return []string{arn[0:startIndex] + parts[2] + arn[endIndex+2:]}
		case "urlencode":
			if len(parts) != 2 {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}

			arns := subARNParameters(parts[1], call, true)
			if len(arns) < 1 {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}
			if arns[0] == "" {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}

			return []string{arn[0:startIndex] + url.QueryEscape(arns[0]) + arn[endIndex+2:]}
		case "many":
			manyParts := []string{}

			for _, part := range parts[1:] {
				arns := subARNParameters(part, call, true)
				if len(arns) < 1 {
					return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
				}
				if arns[0] == "" {
					return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
				}

				manyParts = append(manyParts, arns[0])
			}

			return manyParts
		case "regex":
			if len(parts) != 3 {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}

			arns := subARNParameters(parts[1], call, true)
			if len(arns) < 1 {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}
			if arns[0] == "" {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}

			r := regexp.MustCompile(parts[2]) // TODO: $ escape for regex?
			groups := r.FindStringSubmatch(arns[0])

			if len(groups) < 2 {
				return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
			}

			return []string{arn[0:startIndex] + groups[1] + arn[endIndex+2:]}
		default: // unknown function
			return []string{arn[0:startIndex] + "*" + arn[endIndex+2:]}
		}
	}

	return []string{arn}
}

func getStatementsForProxyCall(call Entry) (statements []Statement) {
	lowerPriv := strings.ToLower(fmt.Sprintf("%s.%s", call.Service, call.Method))

	var iamMap iamMapBase
	err := json.Unmarshal(bIAMMap, &iamMap)
	if err != nil {
		log.Fatal(err)
	}

	var iamDef []iamDefService
	err = json.Unmarshal(bIAMSAR, &iamDef)
	if err != nil {
		panic(err)
	}

	for iamMapMethodName, iamMapMethods := range iamMap.SDKMethodIAMMappings {
		if strings.ToLower(iamMapMethodName) == lowerPriv {
			for _, mappedPriv := range iamMapMethods {
				resources := []string{}

				// arn_override
				if mappedPriv.ArnOverride.Template != "" {
					arns := resolveSpecials(mappedPriv.ArnOverride.Template, call)

					for _, arn := range arns {
						resources = append(resources, subARNParameters(arn, call, false)...) // sub full parameters and add to resources
					}
				}

				// resource_mappings
				if len(resources) == 0 {
					for _, service := range iamDef { // in the SAR
						if service.Prefix == strings.ToLower(call.Service) { // find the service for the call TODO: check mappings for this
							for _, servicePrivilege := range service.Privileges {
								if strings.ToLower(call.Method) == strings.ToLower(servicePrivilege.Privilege) { // find the method for the call
									for _, resourceType := range servicePrivilege.ResourceTypes { // get all resource types for the privilege
										for _, resource := range service.Resources { // go through the service resources
											if resource.Resource == strings.Replace(resourceType.ResourceType, "*", "", -1) && resource.Resource != "" { // match the resource type (doesn't matter if mandatory)
												arns := []string{resource.Arn} // the base ARN template, matrix init
												newArns := []string{}

												// substitute the resource_mappings
												for resMappingVar, resMapping := range mappedPriv.ResourceMappings { // for each mapping
													for _, arn := range arns { // for each of the arn list
														newArns = []string{}
														resMappingTemplates := resolveSpecials(resMapping.Template, call) // get a list of resolved template strings

														for _, resMappingTemplate := range resMappingTemplates {
															variableReplaced := regexp.MustCompile(`\$\{`+resMappingVar+`\}`).ReplaceAllString(arn, strings.ReplaceAll(resMappingTemplate, `$`, `$$`)) // escape $ for regexp
															newArns = append(newArns, variableReplaced)
														}
													}
													arns = newArns
												}

												for _, arn := range arns {
													resources = append(resources, subARNParameters(arn, call, false)...) // sub full parameters and add to resources
												}
											}
										}
									}
								}
							}
						}
					}
				}

				// default (last ditch)
				if len(resources) == 0 {
					resources = []string{"*"}
				}

				statements = append(statements, Statement{
					Effect:   "Allow",
					Resource: resources,
					Action:   []string{mappedPriv.Action},
				})
			}
		}
	}

	return statements
}

func subARNParameters(arn string, call Entry, specialsOnly bool) []string {
	arns := []string{arn} // matrix

	// parameter substitution
	for paramVarName, params := range call.Parameters {
		newArns := []string{}
		for _, param := range params {
			for i := range arns {
				arn = regexp.MustCompile(`\$\{`+paramVarName+`\}`).ReplaceAllString(arns[i], param) // might have dupes but resolved out later

				newArns = append(newArns, arn)
			}
		}
		arns = newArns
	}

	if specialsOnly {
		if len(arns) != 1 {
			return []string{}
		}
		matched, _ := regexp.Match(`\$\{.+?\}`, []byte(arns[0]))
		if matched {
			return []string{}
		}
		return arns
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
		arn = regexp.MustCompile(`\$\{.+?\}`).ReplaceAllString(arn, "*") // TODO: preserve ${aws:*} variables

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
