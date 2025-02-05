package kmiptest

import (
	"encoding/xml"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/ttlv"

	"github.com/stretchr/testify/require"
)

var (
	nowRe = regexp.MustCompile(`"\$NOW((\-|\+)\d+)?"`)
	varRe = regexp.MustCompile(`"\$[A-Za-z0-9_]+"`)
)

type TestCase struct {
	RequestMessage  kmip.RequestMessage
	ResponseMessage kmip.ResponseMessage
}

type TestSuite struct {
	Version   string
	File      string
	TestCases []TestCase
}

func (ts TestSuite) Name() string {
	return ts.Version + "/" + ts.File
}

func (ts *TestSuite) DecodeTTLV(d *ttlv.Decoder) error {
	for d.Tag() == kmip.TagRequestMessage {
		tc := TestCase{}
		if err := d.TagAny(kmip.TagRequestMessage, &tc.RequestMessage); err != nil {
			return err
		}
		if err := d.TagAny(kmip.TagResponseMessage, &tc.ResponseMessage); err != nil {
			return err
		}
		ts.TestCases = append(ts.TestCases, tc)
	}
	return nil
}

func (ts *TestSuite) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	dec, err := ttlv.NewXMLFromDecoder(d)
	if err != nil {
		return err
	}
	return ts.DecodeTTLV(&dec)
}

func ListTestSuites(t TestingT, root, version string) []string {
	direntry, err := os.ReadDir(root + "/" + version)
	require.NoError(t, err)

	names := []string{}
	for _, e := range direntry {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	return names
}

func LoadTestSuite(t TestingT, root, version, file string) TestSuite {
	f, err := os.ReadFile(root + "/" + version + "/" + file)
	require.NoError(t, err)

	f = nowRe.ReplaceAllFunc(f, func(b []byte) []byte {
		now := time.Now()
		offset, _ := strconv.ParseInt(string(b[4:]), 10, 64)
		t := now.Add(time.Duration(offset) * time.Second)
		res := []byte{'"'}
		res = t.AppendFormat(res, time.RFC3339)
		return append(res, '"')
	})
	f = varRe.ReplaceAll(f, []byte(`"DEADBEEFCAFE"`))

	ts := TestSuite{
		Version: version,
		File:    file,
	}
	err = xml.Unmarshal(f, &ts)
	require.NoError(t, err)
	return ts
}

var TestCaseVersions = []string{"v1.0", "v1.1", "v1.2", "v1.3", "v1.4"}

var UnsupportedTestCases = []string{
	"v1.0/TC_134_10_Register_Key_Pair_Certify_and_Re_certify_Public_Key.xml",
	"v1.0/TC_NP_1_10_Put.xml",
	"v1.0/TC_NP_2_10_Notify_Put.xml",
	"v1.1/TC_134_11_Register_Key_Pair_Certify_and_Re_certify_Public_Key.xml",
	"v1.1/TC_NP_1_11_Put.xml",
	"v1.1/TC_NP_2_11_Notify_Put.xml",
	"v1.2/TC_134_12_Register_Key_Pair_Certify_and_Re_certify_Public_Key.xml",
	"v1.2/TC_NP_1_12_Put.xml",
	"v1.2/TC_NP_2_12_Notify_Put.xml",
	"v1.2/TC_SJ_1_12_Create_and_SplitJoin.xml",
	"v1.2/TC_SJ_2_12_Register_and_Split_Join.xml",
	"v1.2/TC_SJ_3_12_Join_Split_Keys.xml",
	"v1.2/TC_SJ_4_12_Register_and_Split_Join_with_XOR.xml",
	"v1.4/TC-DERIVEKEY-1-10.xml",
	"v1.4/TC-NP-1-14.xml",
	"v1.4/TC-SJ-1-14.xml",
}
