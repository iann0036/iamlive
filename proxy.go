package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/elazarl/goproxy"
)

//go:embed service/*
var serviceFiles embed.FS

var serviceDefinitions []ServiceDefinition

func createProxy(addr string) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = log.New(io.Discard, "", log.LstdFlags)
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) { // TODO: Move to onResponse for HTTP response codes
		body, _ := ioutil.ReadAll(req.Body)

		isAWSHostname, _ := regexp.MatchString(`^.*\.amazonaws\.com(?:\.cn)?$`, req.Host)
		if isAWSHostname {
			handleAWSRequest(req, body, 200)
		}

		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		return req, nil
	})
	log.Fatal(http.ListenAndServe(addr, proxy))
}

type ServiceDefinition struct {
	Version    string                      `json:"version"`
	Metadata   ServiceDefinitionMetadata   `json:"metadata"`
	Operations map[string]ServiceOperation `json:"operations"`
	Shapes     map[string]interface{}      `json:"shapes"`
}

type ServiceOperation struct {
	Input  ServiceStructure `json:"input"`
	Output ServiceStructure `json:"output"`
}

type ServiceStructure struct {
	Shape        string                      `json:"shape"`
	Type         string                      `json:"type"`
	Member       *ServiceStructure           `json:"member"`
	Members      map[string]ServiceStructure `json:"members"`
	LocationName string                      `json:"locationName"`
}

type ServiceDefinitionMetadata struct {
	APIVersion       string `json:"apiVersion"`
	EndpointPrefix   string `json:"endpointPrefix"`
	JSONVersion      string `json:"jsonVersion"`
	Protocol         string `json:"protocol"`
	ServiceFullName  string `json:"serviceFullName"`
	ServiceID        string `json:"serviceId"`
	SignatureVersion string `json:"signatureVersion"`
	TargetPrefix     string `json:"targetPrefix"`
	UID              string `json:"uid"`
}

func readServiceFiles() {
	files, err := serviceFiles.ReadDir("service")
	if err != nil {
		panic(err)
	}

	for _, dirEntry := range files {
		file, err := serviceFiles.Open("service/" + dirEntry.Name())
		if err != nil {
			panic(err)
		}

		data, err := ioutil.ReadAll(file)
		if err != nil {
			panic(err)
		}

		var def ServiceDefinition
		if json.Unmarshal(data, &def) != nil {
			panic(err)
		}

		serviceDefinitions = append(serviceDefinitions, def)
	}
}

func flatten(top bool, flatMap map[string][]string, nested interface{}, prefix string) error {
	assign := func(newKey string, v interface{}) error {
		switch v.(type) {
		case map[string]interface{}, []interface{}:
			if err := flatten(false, flatMap, v, newKey); err != nil {
				return err
			}
		default:
			flatMap[newKey] = append(flatMap[newKey], fmt.Sprintf("%v", v))
		}

		return nil
	}

	switch nested.(type) {
	case map[string]interface{}:
		for k, v := range nested.(map[string]interface{}) {
			if top {
				assign(k, v)
			} else {
				assign(prefix+"."+k, v)
			}
		}
	case []interface{}:
		for _, v := range nested.([]interface{}) {
			assign(prefix+"[]", v)
		}
	default:
		return fmt.Errorf("invalid object type")
	}

	return nil
}

func handleAWSRequest(req *http.Request, body []byte, respCode int) {
	host := req.Host
	//uri := req.RequestURI

	var serviceDef ServiceDefinition
	endpointPrefix := strings.Split(host, ".")[0]
	for _, serviceDefinition := range serviceDefinitions {
		if serviceDefinition.Metadata.EndpointPrefix == endpointPrefix { // TODO: Ensure latest version
			serviceDef = serviceDefinition
		}
	}

	params := make(map[string][]string)
	action := "*"

	var bodyJSON interface{}
	err := json.Unmarshal(body, &bodyJSON)

	if err == nil {
		// JSON schema
		action = strings.Split(req.Header.Get("X-Amz-Target"), ".")[1] // TODO: error handle

		flatten(true, params, bodyJSON, "")
	} else {
		// URL param schema
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return
		}

		if len(vals["Action"]) != 1 || len(vals["Version"]) != 1 {
			return
		}
		action = vals["Action"][0]

		if serviceDef.Operations[action].Input.Type == "structure" {
			for k, v := range vals {
				if k != "Action" && k != "Version" {
					normalizedK := regexp.MustCompile(`\.member\.[0-9]+`).ReplaceAllString(k, "[]")
					normalizedK = regexp.MustCompile(`\.[0-9]+`).ReplaceAllString(normalizedK, "[]")

					/*
						propReference := findPropReference(serviceDef.Operations[action].Input, normalizedK, "", "")
						if propReference != "" {
							if len(params[propReference]) > 0 {
								params[propReference] = append(params[propReference], v...)
							} else {
								params[propReference] = v
							}
						}
					*/

					if len(params[normalizedK]) > 0 { // TODO: Check logic here
						params[normalizedK] = append(params[normalizedK], v...)
					} else {
						params[normalizedK] = v
					}

					//fmt.Printf("k=%v,v=%v\n", k, v)
				}
			}
		}
	}

	region := "us-east-1"
	re, _ := regexp.Compile(`\.(.+)\.amazonaws\.com(?:\.cn)?$`)
	matches := re.FindStringSubmatch(host)
	if len(matches) == 2 {
		region = matches[1]
	}

	callLog = append(callLog, Entry{
		Region:              region,
		Type:                "ProxyCall",
		Service:             serviceDef.Metadata.ServiceID,
		Method:              action,
		Parameters:          params,
		FinalHTTPStatusCode: respCode,
	})

	handleLoggedCall()
}

func findPropReference(obj ServiceStructure, searchProp string, path string, locationPath string) (ret string) {
	// TODO: Shape deref

	switch obj.Type { // TODO: Exhaustive check for other types
	case "boolean", "timestamp", "blob", "map":
		return ""
	case "structure":
		for k, v := range obj.Members {
			if obj.LocationName != "" {
				if locationPath == "" {
					locationPath = obj.LocationName
				} else {
					locationPath = fmt.Sprintf("%s.%s", locationPath, obj.LocationName)
				}
			}
			newPath := fmt.Sprintf("%s.%s", path, k)
			if path == "" {
				newPath = k
			}

			ret = findPropReference(v, searchProp, newPath, locationPath)
			if ret != "" {
				return ret
			}
		}
	case "long", "float", "integer", "", "string":
		if obj.LocationName != "" {
			if locationPath == "" {
				locationPath = obj.LocationName
			} else {
				locationPath = fmt.Sprintf("%s.%s", locationPath, obj.LocationName)
			}
		} else {
			splitPath := strings.Split(path, ".")
			if locationPath == "" {
				locationPath = splitPath[len(splitPath)-1]
			} else {
				locationPath = fmt.Sprintf("%s.%s", locationPath, splitPath[len(splitPath)-1])
			}
		}
		if locationPath == searchProp {
			return path
		}
	case "list":
		if obj.LocationName != "" {
			if locationPath == "" {
				locationPath = fmt.Sprintf("%s[]", obj.LocationName)
			} else {
				locationPath = fmt.Sprintf("%s.%s[]", locationPath, obj.LocationName)
			}

			if locationPath == searchProp {
				return path
			}
		}

		newPath := fmt.Sprintf("%s[]", path)

		ret = findPropReference(*obj.Member, searchProp, newPath, locationPath)
		if ret != "" {
			return ret
		}
	}

	return ""
}
