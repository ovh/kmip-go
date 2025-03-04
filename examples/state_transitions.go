package main

import (
	"fmt"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
)

// If the operation that creates or registers the object contains an Activation Date
// that has already occurred, then the state immediately transitions from Pre-Active to Active.
func test_state_transitions1(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("test-state").
		WithAttribute(kmip.AttributeNameActivationDate, time.Now().AddDate(0, 0, -1)).
		MustExec()

	assertState(client, res.UniqueIdentifier, kmip.StateActive)

	client.Revoke(res.UniqueIdentifier).MustExec()
	client.Destroy(res.UniqueIdentifier).MustExec()
}

// The transition from Pre-Active to Compromised is caused by a client issuing a Revoke operation
// with a Revocation Reason of Compromised.
func test_state_transitions3(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("test-state").
		MustExec()

	assertState(client, res.UniqueIdentifier, kmip.StatePreActive)

	client.Revoke(res.UniqueIdentifier).WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).MustExec()
	assertState(client, res.UniqueIdentifier, kmip.StateCompromised)
	client.Destroy(res.UniqueIdentifier).MustExec()
	assertState(client, res.UniqueIdentifier, kmip.StateDestroyedCompromised)
}

// The transition from Pre-Active to Active SHALL occur in one of three ways:
//  1. The Activation Date is reached.
func test_state_transitions4_1(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("test-state").
		WithAttribute(kmip.AttributeNameActivationDate, time.Now().Add(15*time.Second)).
		MustExec()

	assertState(client, res.UniqueIdentifier, kmip.StatePreActive)
	time.Sleep(16 * time.Second)
	assertState(client, res.UniqueIdentifier, kmip.StateActive)

	client.Revoke(res.UniqueIdentifier).WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).MustExec()
	client.Destroy(res.UniqueIdentifier).MustExec()
}

// The transition from Pre-Active to Active SHALL occur in one of three ways:
//  2. A client successfully issues a Modify Attribute operation, modifying the Activation Date to a
//     date in the past, or the current date.
func test_state_transitions4_2(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("test-state").
		WithAttribute(kmip.AttributeNameActivationDate, time.Now().AddDate(1, 0, 0)).
		MustExec()

	assertState(client, res.UniqueIdentifier, kmip.StatePreActive)

	client.ModifyAttribute(res.UniqueIdentifier, kmip.AttributeNameActivationDate, time.Now().AddDate(0, 0, -1)).MustExec()

	assertState(client, res.UniqueIdentifier, kmip.StateActive)

	client.Revoke(res.UniqueIdentifier).WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).MustExec()
	client.Destroy(res.UniqueIdentifier).MustExec()
}

// The transition from Active to Deactivated SHALL occur in one of three ways:
//  1. The object's Deactivation Date is reached
func test_state_transitions6_1(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("test-state").
		WithAttribute(kmip.AttributeNameActivationDate, time.Now()).
		WithAttribute(kmip.AttributeNameDeactivationDate, time.Now().Add(15*time.Second)).
		MustExec()
	assertState(client, res.UniqueIdentifier, kmip.StateActive)
	time.Sleep(16 * time.Second)
	assertState(client, res.UniqueIdentifier, kmip.StateDeactivated)

	client.Revoke(res.UniqueIdentifier).WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).MustExec()
	client.Destroy(res.UniqueIdentifier).MustExec()
}

// The transition from Active to Deactivated SHALL occur in one of three ways:
//  3. The client successfully issues a Modify Attribute operation, modifying the Deactivation Date
//     to a date in the past, or the current date.
func test_state_transitions6_3(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("test-state").
		WithAttribute(kmip.AttributeNameActivationDate, time.Now()).
		WithAttribute(kmip.AttributeNameDeactivationDate, time.Now().AddDate(1, 0, 0)).
		MustExec()
	assertState(client, res.UniqueIdentifier, kmip.StateActive)

	client.ModifyAttribute(res.UniqueIdentifier, kmip.AttributeNameDeactivationDate, time.Now().AddDate(0, 0, -1)).MustExec()

	assertState(client, res.UniqueIdentifier, kmip.StateDeactivated)

	client.Revoke(res.UniqueIdentifier).WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).MustExec()
	client.Destroy(res.UniqueIdentifier).MustExec()
}

// The transition from Deactivated to Compromised is caused by a client issuing a Revoke operation
// with a Revocation Reason of Compromised.
func test_state_transitions8(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("test-state").
		WithAttribute(kmip.AttributeNameActivationDate, time.Now()).
		WithAttribute(kmip.AttributeNameDeactivationDate, time.Now().AddDate(-11, 0, 0)).
		MustExec()
	assertState(client, res.UniqueIdentifier, kmip.StateDeactivated)

	client.Revoke(res.UniqueIdentifier).WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).MustExec()

	assertState(client, res.UniqueIdentifier, kmip.StateCompromised)

	client.Destroy(res.UniqueIdentifier).MustExec()
	assertState(client, res.UniqueIdentifier, kmip.StateDestroyedCompromised)
}

// The transition from Destroyed to Destroyed Compromised is caused by a client issuing a Revoke
// operation with a Revocation Reason of Compromised.
func test_state_transitions10(client *kmipclient.Client) {
	res := client.Create().AES(256, kmip.Encrypt|kmip.Decrypt).
		WithName("test-state").
		WithAttribute(kmip.AttributeNameCryptographicUsageMask, kmip.Encrypt|kmip.Decrypt).
		MustExec()
	client.Destroy(res.UniqueIdentifier).MustExec()
	assertState(client, res.UniqueIdentifier, kmip.StateDestroyed)

	client.Revoke(res.UniqueIdentifier).WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).MustExec()
	assertState(client, res.UniqueIdentifier, kmip.StateDestroyedCompromised)
}

// Test some state transition defined in the KMIP spec.
func test_state_transitions(client *kmipclient.Client) {
	test_state_transitions1(client)
	test_state_transitions3(client)
	test_state_transitions4_1(client)
	test_state_transitions4_2(client)
	test_state_transitions6_1(client)
	test_state_transitions6_3(client)
	test_state_transitions8(client)
	test_state_transitions10(client)
}

func assertState(client *kmipclient.Client, id string, expected kmip.State) {
	res := client.GetAttributes(id).WithAttributes(kmip.AttributeNameState).MustExec()

	current := res.Attribute[0].AttributeValue.(kmip.State)
	if current != expected {
		panic(fmt.Sprintf("Unexpected kmip object state. Expected %d, got %d", expected, current))
	}
}
