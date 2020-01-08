package client

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"strings"

	zenwinrm "github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

const SoapXMLMimeType = "application/soap+xml"

// See init to learn why this exists.
var dummyEndpoint = zenwinrm.NewEndpoint("", 0, true, false, nil, nil, nil, 0)

type Client struct {
	ctx        context.Context
	httpClient *http.Client
	password   string
	zenClient  *zenwinrm.Client
	url        string
	user       string
}

func NewClient(
	useTLS bool,
	host string,
	port int,
	user, password string,
	httpClient *http.Client,
	ctx context.Context) (*Client, error) {
	c := &Client{
		ctx:        ctx,
		httpClient: httpClient,
		password:   password,
		url:        FormatURL(useTLS, host, port),
		user:       user,
	}
	if c.ctx == nil {
		return nil, fmt.Errorf("ctx must not be nil")
	}
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}
	err := c.init()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// FormatURL formats the HTTP URL for Windows server remote management.
func FormatURL(useTLS bool, host string, port int) string {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d/wsman", scheme, host, port)
}

// See init to learn why this adapter exists.
type zenTransporterAdapter struct {
	client *Client
}

func (t *zenTransporterAdapter) Transport(endpoint *zenwinrm.Endpoint) error {
	return nil
}

func (t *zenTransporterAdapter) Post(zenClient *zenwinrm.Client, request *soap.SoapMessage) (string, error) {
	return t.client.doPost(request)
}

func (c *Client) init() error {
	var err error
	// We now initialize zenClient with a custom transport, reasoning is as follows:
	// 1. winrm unnecessarily creates a http.Client instance for each request: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/http.go#L82
	// 2. winrm does not close the response body in the error case: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/http.go#L95
	// 3. winrm's check for the response content type is fishy: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/http.go#L21
	//    See doPost for a more solid approach.
	params := *zenwinrm.DefaultParameters
	params.TransportDecorator = func() zenwinrm.Transporter {
		return &zenTransporterAdapter{
			client: c,
		}
	}
	c.zenClient, err = zenwinrm.NewClientWithParameters(
		dummyEndpoint, // values are computed based on this argument, or copied from this argument by winrm, but these are invisible side
		// effects that have no effect on the behavior, if you study the code.
		"", // username is purposely set to the empty string since doPost handles authentication
		"", // password is purposely set to the empty string since doPost handles authentication
		&params,
	)
	return err
}

func (c *Client) doPost(request *soap.SoapMessage) (string, error) {
	method := http.MethodPost
	requestString := request.String()
	req, err := http.NewRequestWithContext(c.ctx, method, c.url, strings.NewReader(requestString))
	if err != nil {
		return "", fmt.Errorf("error creating request %s %#v: %w", method, c.url, err)
	}
	req.Header.Set("Content-Type", SoapXMLMimeType+";charset=UTF-8")
	req.SetBasicAuth(c.user, c.password)
	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error doing HTTP request %s %#v: %w", method, c.url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		var errorInfo strings.Builder
		_, err = io.CopyN(&errorInfo, res.Body, 4*1024)
		if err != nil {
			log.Printf("error while reading response body of HTTP request %s %#v: %v", method, c.url, err)
		}
		return "", fmt.Errorf("server responded to %s %#v with unexpected HTTP status %d, body prefix: %#v", method, c.url, res.StatusCode, errorInfo.String())
	}
	contentTypeStrings := res.Header["Content-Type"]
	if len(contentTypeStrings) != 1 {
		return "", fmt.Errorf("server responded to %s %#v with HTTP status %d but the response has %d Content-Type headers", method, c.url, res.StatusCode, len(contentTypeStrings))
	}
	mimeType, _, err := mime.ParseMediaType(contentTypeStrings[0])
	if mimeType != SoapXMLMimeType {
		return "", fmt.Errorf("server responded to %s %#v with HTTP status %d but the Content-Type has unexpected mime type %#v", method, c.url, res.StatusCode, mimeType)
	}
	resBodyData, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error while reading response body of HTTP request %s %#v: %w", method, c.url, err)
	}
	// zenwinrm requires a string so we convert from []byte.
	// go defines strings to contain UTF-8 encoded text, but this is not necessarily the case here.
	// This is not a problem however, since zenwinrm reinterpets the string as bytes later on: https://github.com/masterzen/winrm/blob/1d17eaf15943ca3554cdebb3b1b10aaa543a0b7e/shell.go#L19
	return string(resBodyData), nil
}

// CreateShell creates a cmd.exe Shell that can be used to run commands.
func (c *Client) CreateShell() (*zenwinrm.Shell, error) {
	return c.zenClient.CreateShell()
}
