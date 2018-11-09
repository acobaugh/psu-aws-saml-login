package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/RobotsAndPencils/go-saml"
	"github.com/alexflint/go-arg"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
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

type awsRole struct {
	PrincipalARN string
	RoleARN      string
}

type args_t struct {
	ExportEnv bool   `arg:"-e",help:"Provide 'export foo = bar' output to copy/paste into another terminal"`
	User      string `arg:"-u",help:"Access Account username"`
	Role      string `arg:"--role",help:"AWS IAM role arn to assume"`
}

const AWS_SAML_ROLE_ATTRIBUTE = "https://aws.amazon.com/SAML/Attributes/Role"
const IDP_URL = "https://as1.fim.psu.edu/idp/profile/SAML2/Unsolicited/SSO"
const AWS_IDP_REQUEST = "providerId=urn:amazon:webservices"

func main() {
	var args args_t
	arg.MustParse(&args)

	assertion, err := shibLogin(args, IDP_URL, AWS_IDP_REQUEST)

	response, err := saml.ParseEncodedResponse(assertion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SAMLResponse parse: %s\n", err)
		os.Exit(1)
	}

	var roles []awsRole
	for _, r := range response.GetAttributeValues(AWS_SAML_ROLE_ATTRIBUTE) {
		sp := strings.Split(r, ",")
		roles = append(roles, awsRole{PrincipalARN: sp[0], RoleARN: sp[1]})
	}

	// no roles
	if len(roles) == 0 {
		fmt.Fprintf(os.Stderr, "No AWS roles returned. Perhaps you do not have access to any accounts through this SAML provider?")
		os.Exit(1)
	}

	// get selection
	selection := -1

	if args.Role != "" {
		for r := range roles {
			if args.Role == roles[r].RoleARN {
				selection = r
			}
		}
		if selection == -1 {
			fmt.Fprintf(os.Stderr, "Chosen role \"%s\" not in list of roles returned by SAML assertion. Perhaps you do not have access to this role?", args.Role)
			os.Exit(1)
		}
	} else {
		if len(roles) > 1 {
			// present list of roles
			fmt.Printf("Select the role to assume:\n\n")
			for r := range roles {
				fmt.Printf(" %d. %s\n", r, roles[r].RoleARN)
			}
			reader := bufio.NewReader(os.Stdin)
			for {
				fmt.Printf("\nSelection (0-%d): ", len(roles)-1)
				str, _ := reader.ReadString('\n')
				selection, _ = strconv.Atoi(strings.TrimSpace(str))
				if selection < 0 || selection > len(roles)-1 {
					fmt.Fprintf(os.Stderr, "selection is out of range: %d\n", selection)
				} else {
					break
				}
			}
		}
	}

	// assume role
	sess := session.Must(session.NewSession())
	svc := sts.New(sess)
	token, err := svc.AssumeRoleWithSAML(
		&sts.AssumeRoleWithSAMLInput{
			PrincipalArn:  &roles[selection].PrincipalARN,
			RoleArn:       &roles[selection].RoleARN,
			SAMLAssertion: &assertion,
		})
	if err != nil {
		fmt.Fprintf(os.Stderr, "STS AssumeRoleWithSAML() error: %s\n", err)
		os.Exit(1)
	}
	if args.ExportEnv {
		fmt.Print("============\n")
		fmt.Printf("export AWS_ACCESS_KEY_ID=\"%s\"\n", *token.Credentials.AccessKeyId)
		fmt.Printf("export AWS_SECRET_ACCESS_KEY=\"%s\"\n", *token.Credentials.SecretAccessKey)
		fmt.Printf("export AWS_SESSION_TOKEN=\"%s\"\n", *token.Credentials.SessionToken)
	}
}

func credentials(args args_t) (string, string) {
	reader := bufio.NewReader(os.Stdin)

	var username string
	if args.User == "" {
		fmt.Print("Username: ")
		username, _ = reader.ReadString('\n')
	} else {
		username = args.User
	}

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

func shibLogin(args args_t, idpUrl string, idpRequest string) (string, error) {
	// create our browser
	browser := surf.NewBrowser()
	browser.SetTimeout(30 * time.Second)

	// Send our request to the IdP, which will redirect us to WebAccess
	requestUrl := fmt.Sprintf("%s?%s", idpUrl, idpRequest)
	fmt.Printf("Sending request to IdP: %s\n", requestUrl)
	err := browser.Open(requestUrl)
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
	username, password := credentials(args)

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

	fmt.Print("Enter a passcode or select one of the following options:\n\n")

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
	// token

	fmt.Println()

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
		// find the duo_device with type = token
		tokenId := ""
		for _, d := range duoResults.Devices.Devices {
			if d.Type == "token" {
				tokenId = d.Device
			}
		}
		if tokenId == "" {
			fmt.Fprintf(os.Stderr, "No token devices were returned by the duo service, unable to continue\n")
			os.Exit(1)
		}

		fm.Set("duo_passcode", strconv.Itoa(optint))
		fm.Set("duo_device", tokenId)
		fm.Set("duo_factor", "passcode")
	} else {
		// one of the radio options was selected
		fm.Input("duo_device", devices[optint].Device)
		err = fm.Set("duo_factor", devices[optint].OptionType)
	}

	// submit form
	browser.SetTimeout(60 * time.Second)
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

	return assertion, nil
}
