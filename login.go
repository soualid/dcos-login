// Package dcoslogin provides a way to login to a Community Edition DC/OS cluster unattended
package dcoslogin

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// Debug can be set to true for (very) verbose output, helpful for troubleshooting OAuth issues
var Debug = true

var Jar *cookiejar.Jar
var DeviceID string

// Options has the parameters needed to login to DC/OS
type Options struct {
	ClusterURL *string

	Username *string
	Password *string

	AllowInsecureTLS *bool
}

// Login simulates a user loging in to a Community Edition DC/OS cluster using Github credentials
func Login(o *Options) error {
	client, err := httpClient(*o.AllowInsecureTLS)
	if err != nil {
		return err
	}

	// Hit the DC/OS login endpoint to retrieve the clusterID and the clientID
	clusterID, clientID, err := client.initiateLogin(*o.ClusterURL)
	if err != nil {
		return err
	}

	// DC/OS uses Auth0, initiate the session to get the CSRF token
	csrfToken, err := client.initiateAuth0(clusterID, clientID)
	if err != nil {
		return err
	}

	// Authenticate with Github, get the Auth0 token back
	auth0Token, err := client.githubAuthenticate(csrfToken, *o.Username, *o.Password)
	if err != nil {
		return err
	}

	// Exchange the Auth0 token for a DC/OS token
	dcosToken, err := client.finishLogin(*o.ClusterURL, auth0Token)
	if err != nil {
		return err
	}

	fmt.Println(dcosToken)

	return nil
}

type client struct {
	http.Client
}

func httpClient(allowInsecureTLS bool) (*client, error) {
	jar, err := cookiejar.New(nil)
	Jar = jar
	if err != nil {
		return nil, err
	}

	return &client{
		http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: allowInsecureTLS},
			},
			Jar: jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				//debug(req.Method, req.URL)
				fmt.Printf("redirect to ---> %v\n\n", req.URL)
				if strings.Contains(req.URL.String(), "https://github.com/login/oauth/authorize?client_id") {
					fmt.Println("stopping redirection")
					//return errors.New("net/http: use last response")
				}
				for _, r := range via {
					for _, c := range r.Cookies() {
						fmt.Printf("---> %v - %v : %v\n", r.URL.String(), c.Name, c.Value)
					}
				}

				for _, c := range req.Cookies() {
					fmt.Printf("---> %v - %v : %v\n", req.URL.String(), c.Name, c.Value)
				}
				return nil
			},
		},
	}, nil
}

func (c *client) Get(endpoint string, query url.Values) (*http.Response, error) {
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	debug("GET", endpoint)

	res, err := c.Client.Get(endpoint)
	if err != nil {
		return nil, err
	}

	if err := checkStatus(res); err != nil {
		return nil, err
	}

	return res, nil
}

func (c *client) PostForm(endpoint string, data url.Values) (*http.Response, error) {
	req, _ := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	/*
		if ghSession != "" {
			fmt.Printf("--- have a session, using %v %v\n\n", endpoint, ghSession)
			req.AddCookie(&http.Cookie{Name: "_gh_sess", Value: ghSession, Path: "/"})
		}
	*/
	//
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, _ := c.Client.Do(req)
	fmt.Printf("Got %v for %v\n\n", res.StatusCode, endpoint)
	/*
		if err != nil {
			return nil, err
		}

		if err := checkStatus(res); err != nil {
			return nil, err
		}
	*/
	return res, nil
}

func (c *client) PostJSON(endpoint string, data interface{}) (*http.Response, error) {
	var encoded bytes.Buffer
	err := json.NewEncoder(&encoded).Encode(data)
	if err != nil {
		return nil, err
	}

	res, err := c.Client.Post(endpoint, "application/json", &encoded)
	if err != nil {
		return nil, err
	}

	if err := checkStatus(res); err != nil {
		return nil, err
	}

	return res, nil
}

func (c *client) initiateLogin(clusterURL string) (string, string, error) {
	res, err := c.Get(clusterURL+"/login", url.Values{
		"redirect_uri": []string{"urn:ietf:wg:oauth:2.0:oob"},
	})
	if err != nil {
		return "", "", err
	}

	clusterID := res.Request.URL.Query().Get("cluster_id")
	clientID := res.Request.URL.Query().Get("client")

	return clusterID, clientID, nil
}

func (c *client) initiateAuth0(clusterID, clientID string) (string, error) {
	res, err := c.Get("https://dcos.auth0.com/authorize", url.Values{
		"scope":         []string{"openid email"},
		"response_type": []string{"token"},
		"connection":    []string{"github"},
		"cluster_id":    []string{clusterID},
		"client_id":     []string{clientID},
		"owp":           []string{"true"},
	})
	if err != nil {
		return "", err
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", err
	}
	/*
		for _, cookie := range res.Cookies() {
			fmt.Printf("- auth0 cookie: %v : %v\n\n", cookie.Name, cookie.Value)
			if cookie.Name == "_gh_sess" {
				u, _ := url.Parse("https://github.com/session")
				var cookies []*http.Cookie
				cookies = append(cookies, cookie)
				Jar.SetCookies(u, cookies)
			}
		}
	*/
	csrf, found := doc.Find(`input[name="authenticity_token"]`).Attr("value")
	if !found {
		return "", errors.New("Unable to extract CSRF token from response")
	}
	fmt.Printf("CSRF: %v\n", csrf)
	return csrf, nil
}

func (c *client) githubAuthenticate(csrfToken, username, password string) (string, error) {
	/*
		loginRes, err := c.Get("https://github.com/login", url.Values{})
		if err != nil {
			return "", err
		}

		for _, cookie := range loginRes.Cookies() {
			fmt.Printf("- cookie: %v : %v\n\n", cookie.Name, cookie.Value)
			if cookie.Name == "_gh_sess" {
				ghSession = cookie.Value
			}
		}

		doc, err := goquery.NewDocumentFromResponse(loginRes)
		if err != nil {
			return "", err
		}

		csrf, found := doc.Find(`input[name="authenticity_token"]`).Attr("value")
		if !found {
			return "", errors.New("Unable to extract CSRF token from response")
		}

		fmt.Println(csrf)
		fmt.Println(url.QueryEscape(csrf))
	*/
	sessionRes, err := c.PostForm("https://github.com/session", url.Values{
		"login":              []string{username},
		"password":           []string{password},
		"authenticity_token": []string{csrfToken},
	})

	/*
		body, err := ioutil.ReadAll(sessionRes.Body)
		bodyString := string(body)
		fmt.Printf("doc: %v\n\n", bodyString)

	*/

	for _, cookie := range sessionRes.Cookies() {
		fmt.Printf("- cookie: %v : %v\n\n", cookie.Name, cookie.Value)
	}

	u, _ := url.Parse("https://github.com/login/oauth/authorize")
	for _, cookie := range Jar.Cookies(u) {
		if cookie.Name == "_device_id" {
			DeviceID = cookie.Value
		}
	}

	tokenRes, err := c.followLoginRedirect(sessionRes)
	if err != nil {
		return "", err
	}

	return getLoginToken(tokenRes)
}

func (c *client) finishLogin(clusterURL, auth0Token string) (string, error) {
	res, err := c.PostJSON(clusterURL+"/acs/api/v1/auth/login", map[string]string{
		"token": auth0Token,
	})
	if err != nil {
		return "", err
	}

	var output struct {
		Token string
	}
	err = json.NewDecoder(res.Body).Decode(&output)
	if err != nil {
		return "", err
	}

	return output.Token, nil
}

func (c *client) followLoginRedirect(res *http.Response) (*http.Response, error) {
	/*
		body, err := ioutil.ReadAll(res.Body)
		bodyString := string(body)
		fmt.Printf("doc: %v\n\n", bodyString)
	*/
	dump, err := httputil.DumpResponse(res, true)
	if err != nil {
		return nil, err
	}
	/*
		for _, cookie := range res.Cookies() {
			fmt.Printf("- cookie: %v : %v\n\n", cookie.Name, cookie.Value)
			if cookie.Name == "_gh_sess" {
				ghSession = cookie.Value
			}
		}
	*/
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, err
	}

	redirectURL, found := doc.Find(".container div p a").Attr("href")
	// Easy path, no re-authorization
	if found {
		return c.Get(redirectURL, nil)
	}

	var verificationForm *goquery.Selection
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		if action == "/sessions/verified-device" {
			verificationForm = s
		}
	})

	if verificationForm != nil {
		fmt.Print("Device verification required, this is normally required only one time per device so subsequent \ncalls should be non-interactive on this device. Enter the code you received by e-mail:\n")

		reader := bufio.NewReader(os.Stdin)
		verificationCode, _ := reader.ReadString('\n')
		verificationCode = strings.TrimSuffix(verificationCode, "\n")
		q := url.Values{}
		verificationForm.Find("input").Each(func(_ int, input *goquery.Selection) {
			name, _ := input.Attr("name")
			value, _ := input.Attr("value")
			q.Add(name, value)
		})
		q.Del("otp")
		q.Add("otp", verificationCode)

		response, err := c.PostForm("https://github.com/sessions/verified-device", q)
		if response.StatusCode != 200 || err != nil {
			return nil, errors.New("Unexpected Github response during device verification")
		}
		fmt.Printf("verified device cookies: %v\n\n", response.Cookies())
		doc, err = goquery.NewDocumentFromResponse(response)

		redirectURL, found := doc.Find(".container div p a").Attr("href")
		// Easy path, no re-authorization
		if found {
			return c.Get(redirectURL, nil)
		}
	}

	// Check if Github is simply asking for re-authorization
	authorizeForm := doc.Find(`form[action="/login/oauth/authorize"]`)
	if authorizeForm.Length() != 1 {
		debug(string(dump))
		return nil, errors.New("Unexpected Github response")
	}

	// Re-authorize
	q := url.Values{
		"authorize": []string{"1"},
	}
	authorizeForm.Find("input").Each(func(_ int, input *goquery.Selection) {
		name, _ := input.Attr("name")
		value, _ := input.Attr("value")
		q.Add(name, value)
	})

	return c.PostForm("https://github.com/login/oauth/authorize", q)
}

// The DC/OS frontend exposes the token as a variable in a JS script. This (somewhat hackily) extracts it.
func getLoginToken(res *http.Response) (string, error) {
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return "", err
	}

	script := doc.Find(`script[type="text/javascript"]`).Last().Text()

	tokenMatcher := regexp.MustCompile(`var value [^"]+"([^"]+)"[^;]+;`)

	var base64Token string
	if matches := tokenMatcher.FindStringSubmatch(script); len(matches) == 2 {
		base64Token = matches[1]
	} else {
		return "", errors.New("Couldn't extract ACS token from response")
	}

	jsonToken, err := base64.StdEncoding.DecodeString(base64Token)
	if err != nil {
		return "", err
	}

	var jwt struct {
		IDToken string `json:"id_token"`
	}
	err = json.Unmarshal(jsonToken, &jwt)
	if err != nil {
		return "", err
	}

	return jwt.IDToken, nil
}

func checkStatus(res *http.Response) error {
	if res.StatusCode < 200 || res.StatusCode > 206 {
		dump, err := httputil.DumpResponse(res, true)
		if err == nil {
			return fmt.Errorf("Expected status 200 <= code <= 206, got %v\n%s", res.StatusCode, string(dump))
		}

		return fmt.Errorf("Expected status 200 <= code <= 206, got %v", res.StatusCode)
	}

	return nil
}

func debug(a ...interface{}) {
	if Debug {
		log.Println(a...)
	}
}
