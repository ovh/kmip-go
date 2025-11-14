package kmiptest

import (
	"context"
	"testing"

	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"

	"github.com/stretchr/testify/require"
)

func TestClientServer(t *testing.T) {
	client := NewClientAndServer(t, kmipserver.NewBatchExecutor())
	resp, err := client.Request(context.Background(), &payloads.DiscoverVersionsRequestPayload{})
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestHttpClientServer(t *testing.T) {
	client := NewHttpClientAndServer(t, kmipserver.NewBatchExecutor())
	resp, err := client.Request(context.Background(), &payloads.DiscoverVersionsRequestPayload{})
	require.NoError(t, err)
	require.NotNil(t, resp)
}
