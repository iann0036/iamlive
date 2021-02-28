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
	"os"
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
	Shapes     map[string]ServiceStructure `json:"shapes"`
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
	ParentKey    string
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

					resolvedPropertyName := resolvePropertyName(serviceDef.Operations[action].Input, normalizedK, "", "", serviceDef.Shapes)
					if resolvedPropertyName != "" {
						normalizedK = resolvedPropertyName
					}

					if len(params[normalizedK]) > 0 { // TODO: Check logic here
						params[normalizedK] = append(params[normalizedK], v...)
					} else {
						params[normalizedK] = v
					}

					//fmt.Printf("k=%v,v=%v\n", k, v)
				}
			}
		}

		fmt.Println(vals)
		fmt.Println(params)
		os.Exit(0)
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

func resolvePropertyName(obj ServiceStructure, searchProp string, path string, locationPath string, shapes map[string]ServiceStructure) (ret string) {
	if searchProp[len(searchProp)-2:] == "[]" { // trim trailing []
		searchProp = searchProp[:len(searchProp)-2]
	}

	if obj.Shape != "" {
		locationName := obj.LocationName
		obj = shapes[obj.Shape]
		obj.LocationName = locationName
	}

	switch obj.Type { // TODO: Exhaustive check for other types
	case "boolean", "timestamp", "blob", "map":
		return ""
	case "structure":
		for k, v := range obj.Members {
			newPath := fmt.Sprintf("%s.%s", path, k)
			if path == "" {
				newPath = k
			}

			newLocationPath := locationPath + "." + k
			if v.LocationName != "" {
				v.ParentKey = v.LocationName
			} else {
				v.ParentKey = k
			}

			ret = resolvePropertyName(v, searchProp, newPath, newLocationPath, shapes)
			if ret != "" {
				return ret
			}
		}
	case "long", "float", "integer", "", "string":
		key := obj.ParentKey
		if obj.LocationName != "" {
			key = obj.LocationName
		}

		//locationPath = locationPath[:strings.LastIndex(locationPath, ".")] // override last element
		locationPath = fmt.Sprintf("%s.%s", locationPath, key)

		if len(locationPath) > 2 && locationPath[len(locationPath)-2:] == "[]" { // trim trailing []
			locationPath = locationPath[:len(locationPath)-2]
		}
		if locationPath[0] == '.' { // trim leading .
			locationPath = locationPath[1:]
		}

		if strings.ToLower(locationPath) == strings.ToLower(searchProp) {
			fmt.Println("Matching path: " + locationPath)
			return path
		} else {
			fmt.Println("NON-Matching path: " + locationPath + " - " + searchProp)
		}
	case "list":
		newPath := fmt.Sprintf("%s[]", path)
		newLocationPath := fmt.Sprintf("%s[]", locationPath)

		ret = resolvePropertyName(*obj.Member, searchProp, newPath, newLocationPath, shapes)
		if ret != "" {
			return ret
		}
	}

	return ""
}
