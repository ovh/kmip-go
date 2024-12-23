//nolint:unused // This is a test file
package main

import (
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

func cleanupDomain(client *kmipclient.Client) {
	println("Listing all objects")
	resp := client.Locate().MustExec()
	for _, id := range resp.UniqueIdentifier {
		resp := client.GetAttributes(id, kmip.AttributeNameState).MustExec()

		for _, attr := range resp.Attribute {
			if attr.AttributeName == kmip.AttributeNameState && attr.AttributeValue.(kmip.State) == kmip.StateActive {
				println("Revoking", id)
				client.Revoke(id).WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).MustExec()
				break
			}
		}

		println("Deleting", id)
		client.Destroy(id).MustExec()
	}
	println("Deleted", len(resp.UniqueIdentifier), "managed objects")
}

func activateAll(client *kmipclient.Client) {
	println("Listing all objects")
	resp := client.Locate().MustExec()
	for _, id := range resp.UniqueIdentifier {
		resp := client.GetAttributes(id, kmip.AttributeNameState).MustExec()

		for _, attr := range resp.Attribute {
			if attr.AttributeName == kmip.AttributeNameState && attr.AttributeValue.(kmip.State) == kmip.StatePreActive {
				println("Activating", id)
				client.Activate(id).MustExec()
				break
			}
		}
	}
}
