/*
 * Minio Client (C) 2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

type samlAttr struct {
	username   string
	password   string
	providerID string
	idpURL     string
}

const (
	// Identity provider uat is only used for testing purposes.
	idpUATEntryURL = "https://idp-uat.stanford.edu/idp/profile/SAML2/Unsolicited/SSO?providerId=%s"

	// Indentity provider Prod is only used for production purposes.
	idpProdEntryURL = "https://idp.stanford.edu/idp/profile/SAML2/Unsolicited/SSO?providerId=%s"
)

func readSAMLAttr() samlAttr {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	password := string(bytePassword)
	password = strings.TrimSpace(password)
	fmt.Println()

	fmt.Print("SAML Provider id [https://rosalind.stanford.edu]: ")
	providerID, _ := reader.ReadString('\n')
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		providerID = "https://rosalind.stanford.edu/"
	}

	fmt.Print("SAML IdP URL: [https://idp-uat.stanford.edu]: ")
	idpURL, _ := reader.ReadString('\n')
	idpURL = strings.TrimSpace(idpURL)
	if idpURL == "" {
		idpURL = idpUATEntryURL
	}
	fmt.Println()

	return samlAttr{
		username:   username,
		password:   password,
		providerID: providerID,
		idpURL:     idpURL,
	}
}
