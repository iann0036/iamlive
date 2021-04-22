package main

import (
	"flag"
	"github.com/iann0036/iamlive/faillog"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

func TestSimpleRequest(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping e2e test")
	}

	parseConfig()
	flag.Parse()
	loadMaps()
	readServiceFiles()
	*modeFlag = "proxy"

	p := createProxy()
	ts := httptest.NewServer(p)
	defer ts.Close()

	fl := &faillog.Logger{}
	defer fl.Close()

	cmd := exec.Command("aws", "sts", "get-caller-identity")
	cmd.Stdout = fl
	cmd.Stderr = fl
	cmd.Env = append(os.Environ(),
		"AWS_CA_BUNDLE=~/.iamlive/ca.pem",
		"HTTP_PROXY="+ts.URL,
		"HTTPS_PROXY="+ts.URL,
	)

	err := cmd.Run()
	assert.NoError(t, err)

	doc := getPolicyDocument()
	assert.JSONEq(t, `
		{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Allow",
					"Action": [
						"sts:GetCallerIdentity"
					],
					"Resource": "*"
				}
			]
		}
	`, string(doc))

	fl.Success(!t.Failed())
}
