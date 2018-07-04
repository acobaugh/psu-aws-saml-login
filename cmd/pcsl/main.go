package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/RobotsAndPencils/go-saml"
	"github.com/headzoo/surf"
	"github.com/robertkrimen/otto"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"regexp"
	"strconv"
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
	OptionType   string   `json:"omitempty"`
}

const AWS_SAML_ROLE_ATTRIBUTE = "https://aws.amazon.com/SAML/Attributes/Role"

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
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Current URL: %s\n", browser.Url())

	// find our login form
	fm, err := browser.Form("form")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
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
		fmt.Fprintf(os.Stderr, "error: %s", err)
		os.Exit(1)
	}

	// extract duoResults javascript object literal from page
	re := regexp.MustCompile(`var\s+duoResults\s+=\s+({[\S\s]*});`)
	matches := re.FindStringSubmatch(browser.Body())
	if len(matches) != 2 {
		// TODO: handle the case where this account is not enrolled in Duo
		fmt.Fprintf(os.Stderr, "Something went wrong, duoResults variable not present on page after submitting login\n")
		os.Exit(1)
	}

	// use JSON.stringify(eval()) to evaluate the raw JS text and return JSON
	vm := otto.New()
	vm.Set("input", matches[1])
	stringifyOutput, err := vm.Run(`JSON.stringify( eval('('+input+')') )`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON.stringify returned `%s`\n", err)
		os.Exit(1)
	}

	// call otto's .ToString() on duoResultsJSON to turn it from a ott.Value to a string
	duoResultsJSON, err := stringifyOutput.ToString()
	if err != nil {
		fmt.Fprintf(os.Stderr, ".ToString() returned `%s`\n", err)
		os.Exit(1)
	}

	// unmarshal JSON into an object
	var duoResults duoResults_t
	json.Unmarshal([]byte(duoResultsJSON), &duoResults)

	if len(duoResults.Devices.Devices) == 0 {
		fmt.Fprintf(os.Stderr, "No 2FA devices returned: %s", duoResults.Error)
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
			devices[len(devices)-1].OptionType = "push"
			fmt.Printf(" %d. Duo Push to %s\n", len(devices)-1, d.DisplayName)
		}
	}

	// Phone
	for _, d := range duoResults.Devices.Devices {
		if stringInSlice("phone", d.Capabilities) {
			devices = append(devices, d)
			devices[len(devices)-1].OptionType = "phone"
			fmt.Printf(" %d. Phone call to %s\n", len(devices)-1, d.DisplayName)
		}
	}

	// SMS
	for _, d := range duoResults.Devices.Devices {
		if stringInSlice("sms", d.Capabilities) {
			devices = append(devices, d)
			devices[len(devices)-1].OptionType = "sms"
			nextcode := ""
			if d.SmsNextcode != "" {
				nextcode = fmt.Sprintf("(next code starts with %s)", d.SmsNextcode)
			}
			fmt.Printf(" %d. SMS passcodes to %s %s\n", len(devices)-1, d.DisplayName, nextcode)
		}
	}

	// prompt for 2fa option
	var option string
	var optint int
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Passcode or option (1-%d): ", len(devices)-1)
		option, _ = reader.ReadString('\n')

		optint, err = strconv.Atoi(strings.TrimSpace(option))
		if err != nil || optint < 1 {
			fmt.Fprintf(os.Stderr, "Invalid option: %s\n", option)
		} else {
			break
		}
	}

	// find the 2fa form
	fm, err = browser.Form("form")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not locate 2FA form: %s\n", err)
		os.Exit(1)
	}

	// fill out form
	// note: duo_factor is added to the form dynamically, so we Set() instead of Input()
	if optint > len(devices)-1 {
		// selection is larger than the number of options, assume it is a passcode
		fm.Input("duo_passcode", option)
		fm.Set("duo_factor", "passcode")
	} else {
		// one of the radio options was selected
		fm.Input("duo_device", devices[optint].Device)
		err = fm.Set("duo_factor", devices[optint].OptionType)
		fmt.Println(err)
	}

	// submit form
	err = fm.Submit()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when submitting form: %s", err)
		os.Exit(1)
	}

	// pull the assertion out of the response
	doc := browser.Dom()
	s := doc.Find("input[name=SAMLResponse]").First()
	assertion, ok := s.Attr("value")
	if !ok {
		fmt.Fprintf(os.Stderr, "Response did not provide a SAML assertion (SAMLResponse html element)\n")
		os.Exit(1)
	}

	response, err := saml.ParseEncodedResponse(assertion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SAMLResponse parse: %s\n", err)
		os.Exit(1)
	}

	roles := response.GetAttributeValues(AWS_SAML_ROLE_ATTRIBUTE)
	fmt.Printf("%+v\n", roles)
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
