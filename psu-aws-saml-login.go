package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/headzoo/surf"
	"github.com/robertkrimen/otto"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type duoResults_t struct {
	AccountType string `json:"account_type"`
	Devices     struct {
		Devices []struct {
			Capabilities []string `json:"capabilities"`
			Device       string   `json:"device"`
			DisplayName  string   `json:"display_name"`
			SmsNextcode  string   `json:"sms_nextcode,omitempty"`
			Type         string   `json:"type"`
		} `json:"devices"`
	} `json:"devices"`
	Error            string `json:"error"`
	Referrer         string `json:"referrer"`
	Remoteuser       string `json:"remoteuser"`
	RequiredFactors  string `json:"requiredFactors"`
	SatisfiedFactors string `json:"satisfiedFactors"`
	Service          string `json:"service"`
}

func main() {
	timeout, _ := time.ParseDuration("10s")
	idpUrl := "https://as1.fim.psu.edu/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices"
	//awsRoleUrl := "https://aws.amazon.com/SAML/Attributes/Role"

	// create our browser
	browser := surf.NewBrowser()
	browser.SetTimeout(timeout)

	// Send our request to the IdP, which will redirect us to WebAccess
	fmt.Printf("Sending request to IdP: %s\n", idpUrl)
	err := browser.Open(idpUrl)
	if err != nil {
		fmt.Errorf("error: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Current URL: %s\n", browser.Url())

	// find our login form
	fm, err := browser.Form("form")
	if err != nil {
		fmt.Errorf("error: %s\n", err)
		os.Exit(1)
	}

	// Prompt user for creds
	username, password := credentials()

	// submit username/password
	fmt.Printf("Submitting creds to: %s\n", fm.Action())
	fm.Input("login", username)
	fm.Input("password", password)
	err = fm.Submit()
	if err != nil {
		fmt.Errorf("error: %s", err)
		os.Exit(1)
	}

	// extract duoResults javascript object literal from page
	re := regexp.MustCompile(`var\s+duoResults\s+=\s+({[\S\s]*});`)
	matches := re.FindStringSubmatch(browser.Body())
	if len(matches) != 2 {
		fmt.Errorf("Something went wrong, duoResults variable not present on page after submitting login\n")
		os.Exit(1)
	}

	// use JSON.stringify(eval()) to evaluate the raw JS text and return JSON
	vm := otto.New()
	vm.Set("input", matches[1])
	stringifyOutput, err := vm.Run(`JSON.stringify( eval('('+input+')') )`)
	if err != nil {
		fmt.Errorf("JSON.stringify returned `%s`\n", err)
		os.Exit(1)
	}

	// call otto's .ToString()
	duoResultsJSON, err := stringifyOutput.ToString()
	if err != nil {
		fmt.Errorf(".ToString() returned `%s`\n", err)
		os.Exit(1)
	}

	// unmarshal JSON into an object
	var duoResults duoResults_t
	json.Unmarshal([]byte(duoResultsJSON), &duoResults)

	fmt.Printf("%+v\n", duoResults)
}

func credentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	password := string(bytePassword)

	fmt.Println()

	return strings.TrimSpace(username), strings.TrimSpace(password)
}
