//go:build ignore

package main

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"github.com/sarumaj/kagi-proxy/pkg/common"
)

var examples = map[string]common.Policy{
	"path_based_policy.json": {
		common.Deny: common.Ruleset{
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"billing"}}},
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"gift"}}},
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"user_details"}}},
			common.Rule{Path: "/settings", PathType: common.Exact, Query: url.Values{"p": {"api"}, "generate": {"1"}}},
			common.Rule{Path: "/api/user_token", PathType: common.Prefix},
		},
		common.Allow: common.Ruleset{
			common.Rule{Path: "/favicon.ico", PathType: common.Exact},
			common.Rule{Path: `/favicon(?:-\d+x\d+)\.png`, PathType: common.Regex},
		},
	},
}

func main() {
	directory := filepath.Join("..", "..", "examples")
	_ = os.MkdirAll(directory, 0755)
	for filename, policy := range examples {
		log.Printf("Generating %s\n", filename)

		fileDescriptor, err := os.OpenFile(filepath.Join(directory, filename), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer fileDescriptor.Close()

		encoder := json.NewEncoder(fileDescriptor)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(policy); err != nil {
			log.Fatal(err)
		}

		log.Printf("Generated %s\n", filename)
	}
}
