package kmiptest

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadTestSuites(t *testing.T) {
	for _, vers := range TestCaseVersions {
		suites := ListTestSuites(t, "testdata", vers)
		for _, e := range suites {
			name := vers + "/" + e
			if slices.Contains(UnsupportedTestCases, name) {
				continue
			}

			ts := LoadTestSuite(t, "testdata", vers, e)
			require.NotEmpty(t, ts.TestCases)
			require.NotEmpty(t, ts.TestCases)
		}
	}
}
