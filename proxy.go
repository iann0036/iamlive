package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
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
	//TODO: proxy.Logger =
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		body, _ := ioutil.ReadAll(req.Body)

		isAWSHostname, _ := regexp.MatchString(`^.*\.amazonaws\.com(?:\.cn)?$`, req.Host)
		if isAWSHostname {
			handleAWSRequest(req.Host, req.RequestURI, string(body))
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

func handleAWSRequest(host, uri, body string) {
	vals, err := url.ParseQuery(body)
	if err != nil {
		return
	}

	if len(vals["Action"]) != 1 || len(vals["Version"]) != 1 {
		return
	}
	action := vals["Action"][0]
	version := vals["Version"][0]

	var serviceDef ServiceDefinition

	endpointPrefix := strings.Split(host, ".")[0]
	for _, serviceDefinition := range serviceDefinitions {
		if serviceDefinition.Metadata.EndpointPrefix == endpointPrefix && serviceDefinition.Metadata.APIVersion == version {
			serviceDef = serviceDefinition
		}
	}

	params := make(map[string][]string)

	if serviceDef.Operations[action].Input.Type == "structure" {
		for k, v := range vals {
			if k != "Action" && k != "Version" {
				var re = regexp.MustCompile(`\.[0-9]+`)
				normalizedK := re.ReplaceAllString(k, "[]")

				propReference := findPropReference(serviceDef.Operations[action].Input, normalizedK, "", "")
				if propReference != "" {
					if len(params[propReference]) > 0 {
						params[propReference] = append(params[propReference], v...)
					} else {
						params[propReference] = v
					}
				}

				//fmt.Printf("k=%v,v=%v\n", k, v)
			}
		}
	}

	region := "us-east-1"
	// TODO: Better region match

	callLog = append(callLog, Entry{
		Region:              region,
		Type:                "ProxyCall",
		Service:             serviceDef.Metadata.ServiceID,
		Method:              action,
		Parameters:          params,
		FinalHTTPStatusCode: 200,
	})

	handleLoggedCall()
}

func findPropReference(obj ServiceStructure, searchProp string, path string, locationPath string) (ret string) {
	switch obj.Type {
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
	case "long", "float", "":
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
