// access-key creates a new single-principal policy without overwriting any file.
// The high-entropy credential is printed once, after the policy is saved.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
)

func main() {
	name := flag.String("name", "", "principal name")
	role := flag.String("role", "viewer", "viewer, operator or admin")
	out := flag.String("out", "", "new private policy file")
	flag.Parse()
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(*name) || (*role != "viewer" && *role != "operator" && *role != "admin") || *out == "" {
		fmt.Fprintln(os.Stderr, "valid -name, -role and -out are required")
		os.Exit(2)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		fmt.Fprintln(os.Stderr, "credential generation failed")
		os.Exit(1)
	}
	credential := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(credential))
	data, _ := json.MarshalIndent(map[string]any{"principals": []map[string]string{{"name": *name, "role": *role, "sha256": hex.EncodeToString(digest[:])}}}, "", "  ")
	file, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create policy file")
		os.Exit(1)
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		fmt.Fprintln(os.Stderr, "policy save failed; credential was not issued")
		os.Exit(1)
	}
	fmt.Println(credential)
}
