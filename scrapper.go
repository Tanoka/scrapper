package scrapper

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//Global vars to use inside package
var userAg []string
var c conf
var configFile = "proxy.yml"
var useragentsFile = "user_agent.txt"

//Type where to put yaml file content
type conf struct {
	Apikey    string
	ProxyHost string
	ProxyPort string
	Certca    string
}

//Method to set configuration from yaml file.
func (c *conf) getConf() *conf {
	yamlFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		panic(err)
	}
	return c
}

//Initializations of package
//Get proxy config
//Get user agents and seed random generator
func init() {
	c.getConf()

	content, err := ioutil.ReadFile(useragentsFile)
	if err == nil {
		panic(err)
	}
	userAg = strings.Split(string(content), "\n")
	rand.Seed(time.Now().Unix())
}


//Init proxy connection, needed only be create one time, HTTP client is reusable and safe for concurrent use
func initConnection() *http.Client {

	caCert, err := ioutil.ReadFile(c.Certca)
	if err != nil {
		log.Panic(err) // ==	panic(err)
	}

	//certificate
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	//tls config
	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}
	tlsConfig.BuildNameToCertificate()

	//set proxy
	proxyUrl, err := url.Parse("http://" + c.ProxyHost + ":" + c.ProxyPort)
	if err != nil {
		panic(err)
	}

	//set transport: proxy + tls config
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyUrl),
		TLSClientConfig: tlsConfig,
	}

	//set client connection_ transport
	myClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("Redirect")
		},
		Transport: transport,
		Timeout:   time.Second * 4,
	}
	return myClient
}

//Get html from a url
func getPage(myClient *http.Client, url string) (bodyString string, err error) {
	var request *http.Request
	var response *http.Response
	var bodyBytes []byte

	//set resquest
	request, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	//adding proxy authentication to headers request
	if len(c.Apikey) > 0 {
		auth := c.Apikey + ":"
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		request.Header.Add("Proxy-Authorization", basicAuth)
	}
	request.Header.Add("User-agent", userAg[rand.Intn(len(userAg))])
	request.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	request.Header.Add("Accept-Language", "en-US,en;q=0.5")

	response, err = myClient.Do(request)
	if err != nil { //TODO, request error..lost connection, etc.. redirect
		return
	}

	defer response.Body.Close()

	//TODO, log errors?
	switch {
	case response.StatusCode == 429: //Too many requests...
	//TODO, sleep 5 sec??!!
	case response.StatusCode > 300: //not needed??
		err = errors.New("Reponse status > 300: " + string(response.StatusCode))
		return
	}

	bodyBytes, err = ioutil.ReadAll(response.Body) //ReadAll: reads from respnoseBody (io.Reader interface) until an error or EOF and returns the data it read: []byte.
	if err != nil {
		return
	}
	bodyString = string(bodyBytes)

	return
}
