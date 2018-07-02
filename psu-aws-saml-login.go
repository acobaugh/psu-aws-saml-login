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
		Devices []duoDevice_t `json:"devices"`
	} `json:"devices"`
	Error            string `json:"error"`
	Referrer         string `json:"referrer"`
	Remoteuser       string `json:"remoteuser"`
	RequiredFactors  string `json:"requiredFactors"`
	SatisfiedFactors string `json:"satisfiedFactors"`
	Service          string `json:"service"`
}

type duoDevice_t struct {
	Capabilities []string `json:"capabilities"`
	Device       string   `json:"device"`
	DisplayName  string   `json:"display_name"`
	SmsNextcode  string   `json:"sms_nextcode,omitempty"`
	Type         string   `json:"type"`
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
		// TODO: handle the case where this account is not enrolled in Duo
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

	// call otto's .ToString() on duoResultsJSON to turn it from a ott.Value to a string
	duoResultsJSON, err := stringifyOutput.ToString()
	if err != nil {
		fmt.Errorf(".ToString() returned `%s`\n", err)
		os.Exit(1)
	}

	// unmarshal JSON into an object
	var duoResults duoResults_t
	json.Unmarshal([]byte(duoResultsJSON), &duoResults)

	if len(duoResults.Devices.Devices) == 0 {
		fmt.Errorf("No 2FA devices returned, or user not enrolled. %s", duoResults.Error)
		os.Exit(1)
	}

	// present list of 2FA options
	var devices []duoDevice_t                // contain our list of devices
	devices = append(devices, duoDevice_t{}) // skip index 0

	fmt.Printf("Enter a passcode or select one of the following options:\n\n")

	// Push
	for _, d := range duoResults.Devices.Devices {
		if stringInSlice("push", d.Capabilities) {
			devices = append(devices, d)
			fmt.Printf(" %d. Duo Push to %s\n", len(devices)-1, d.DisplayName)
		}
	}

	// Phone
	for _, d := range duoResults.Devices.Devices {
		if stringInSlice("phone", d.Capabilities) {
			devices = append(devices, d)
			fmt.Printf(" %d. Phone call to %s\n", len(devices)-1, d.DisplayName)
		}
	}

	// SMS
	for _, d := range duoResults.Devices.Devices {
		if stringInSlice("sms", d.Capabilities) {
			devices = append(devices, d)
			nextcode := ""
			if d.SmsNextcode != "" {
				nextcode = fmt.Sprintf("(next code starts with %s)", d.SmsNextcode)
			}
			fmt.Printf(" %d. SMS passcodes to %s %s\n", len(devices)-1, d.DisplayName, nextcode)
		}
	}

	// device id -> duo_device
	// passcode -> duo_passcode
	// phone|push|passcode|sms(request new codes) -> duo_factor
	//	fmt.Printf("%+v\n", duoResults)
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

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
