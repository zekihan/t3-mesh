package workflows

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGoCacheDisabledForAgentBuildAndT3Compat(t *testing.T) {
	for _, tt := range []struct {
		file string
		job  string
	}{
		{file: "release.yaml", job: "agent-build"},
		{file: "t3-compat.yaml", job: "compat"},
	} {
		t.Run(tt.job, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", tt.file))
			if err != nil {
				t.Fatal(err)
			}

			var workflow struct {
				Jobs map[string]struct {
					Steps []struct {
						With struct {
							Cache *bool `yaml:"cache"`
						} `yaml:"with"`
						Uses string `yaml:"uses"`
					} `yaml:"steps"`
				} `yaml:"jobs"`
			}

			err = yaml.Unmarshal(data, &workflow)
			if err != nil {
				t.Fatal(err)
			}

			found := false

			for _, step := range workflow.Jobs[tt.job].Steps {
				if !strings.HasPrefix(step.Uses, "actions/setup-go@") {
					continue
				}

				found = true

				if step.With.Cache == nil || *step.With.Cache {
					t.Errorf("%s job %s must set cache: false on actions/setup-go", tt.file, tt.job)
				}
			}

			if !found {
				t.Fatalf("%s job %s is missing an actions/setup-go step", tt.file, tt.job)
			}
		})
	}
}
