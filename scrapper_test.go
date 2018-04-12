package scrapper

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestGetConf(t *testing.T) {
	c.getConf()
	if c.Certca != "file.crt" {
		t.Errorf("Error Certca. Expected %s Actual %s ", "file.crt", c.Certca)
	}
	if c.ProxyPort != "8888" {
		t.Errorf("Error ProxyPort. Expected %s Actual %s ", "8888", c.ProxyPort)
	}
	if c.ProxyHost != "proxy.proxy.com" {
		t.Errorf("Error ProxyHost. Expected %s Actual %s ", "proxy.proxy.com", c.ProxyHost)
	}
	if c.Apikey != "123456789ABCDEFG" {
		t.Errorf("Error Apikey. Expected %s Actual %s ", "123456789ABCDEFG", c.Apikey)
	}
}

func TestGetPage(t *testing.T) {
	myClient := http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return errors.New("Redirect")
	}}

	flagtests := []struct {
		url     string
		contain string
		err     error
	}{
		{"http://www.example.com", "This domain is established to be used for illustrative examples in", nil},
		{"http://ert.ertertfgdfg.xxx", "", errors.New("no such host")},
		{"https://www.example.com", "This domain is established to be used for illustrative examples in", nil},
		{"http://google.com", "", errors.New("Redirect")},
	}

	for _, test := range flagtests {
		body, err := getPage(&myClient, test.url)
		if err != test.err && !strings.Contains(err.Error(), test.err.Error()) {
			t.Errorf("Error. Expected %v Actual %v ", test.err, err)
		}
		if !strings.Contains(body, test.contain) {
			t.Errorf("Error. Expected %s Actual %s ", test.contain, body)
		}
	}
}
