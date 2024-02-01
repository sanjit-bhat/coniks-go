package protocol_test

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/auditlog"
	"github.com/coniks-sys/coniks-go/protocol/auditor"
	"github.com/coniks-sys/coniks-go/protocol/client"
	"github.com/coniks-sys/coniks-go/protocol/directory"
)

var (
	uname1 = "alice"
	uname2 = "bob"
	key1   = []byte("key1")
	key2   = []byte("key2")
)

func registerAndVerify(t *testing.T, d *directory.ConiksDirectory, cc *client.ConsistencyChecks, name string, key []byte) {
	request := &protocol.RegistrationRequest{
		Username: name,
		Key:      key,
	}
	res := d.Register(request)
	err := cc.HandleResponse(protocol.RegistrationType, res, name, key)
	if err != nil {
		t.Fatal(err)
	}
}

func lookupAndVerify(t *testing.T, d *directory.ConiksDirectory, cc *client.ConsistencyChecks, name string) []byte {
	request := &protocol.KeyLookupRequest{
		Username: name,
	}
	res := d.KeyLookup(request)
	err := cc.HandleResponse(protocol.KeyLookupType, res, name, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := res.DirectoryResponse.(*protocol.DirectoryProof).AP[0].Leaf.Value
	return key
}

func newAuditor(t *testing.T, dir *directory.ConiksDirectory, dirPk sign.PublicKey) (auditlog.ConiksAuditLog, [crypto.HashSizeByte]byte) {
	aud := auditlog.New()
	hist := []*protocol.DirSTR{dir.LatestSTR()}
	if err := aud.InitHistory("addr-of-test-dir", dirPk, hist); err != nil {
		t.Fatal("Error making new auditor", err)
	}
	id := auditor.ComputeDirectoryIdentity(hist[0])
	return aud, id
}

func TestAudit(t *testing.T) {
	dir, dirPk := directory.NewTestDirectory(t, true)
	aud, dirId := newAuditor(t, dir, dirPk)
	cReg := client.New(dir.LatestSTR(), true, dirPk)
	cLook1 := client.New(dir.LatestSTR(), true, dirPk)
	cLook2 := client.New(dir.LatestSTR(), true, dirPk)

	registerAndVerify(t, dir, cReg, uname1, key1)
	dir.Update()

	// Clients do lookup.
	retKey1 := lookupAndVerify(t, dir, cLook1, uname1)
	retKey2 := lookupAndVerify(t, dir, cLook2, uname1)

	// Auditor receives the latest dir update.
	newSTRs := protocol.NewSTRHistoryRange([]*protocol.DirSTR{dir.LatestSTR()})
	if err := aud.AuditId(dirId, newSTRs); err != nil {
		t.Fatal("Error auditing dir update", err)
	}

	// Clients talk to the auditor.
	audResp := aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: dirId,
		StartEpoch:     uint64(dir.LatestSTR().Epoch),
		EndEpoch:       uint64(dir.LatestSTR().Epoch)})
	if err := cLook1.CheckEquivocation(audResp); err != nil {
		t.Fatal("Client and auditor had inconsistent views", err)
	}
	if err := cLook2.CheckEquivocation(audResp); err != nil {
		t.Fatal("Client and auditor had inconsistent views", err)
	}

	// Clients check for key match.
	if !bytes.Equal(retKey1, retKey2) {
		t.Fatal("Key mismatch")
	}
}

func TestForkOldDirState_BAD(t *testing.T) {
	dir, dirPk := directory.NewTestDirectory(t, true)
	// dirFork will not see the latest registration.
	dirFork, err := dir.Fork()
	if err != nil {
		t.Fatal("Could not fork", err)
	}
	aud, dirId := newAuditor(t, dir, dirPk)
	cReg := client.New(dir.LatestSTR(), true, dirPk)
	cLook1 := client.New(dir.LatestSTR(), true, dirPk)
	cLook2 := client.New(dir.LatestSTR(), true, dirPk)

	registerAndVerify(t, dir, cReg, uname1, key1)
	dir.Update()

	newSTRs := protocol.NewSTRHistoryRange([]*protocol.DirSTR{dir.LatestSTR()})
	if err := aud.AuditId(dirId, newSTRs); err != nil {
		t.Fatal("Error auditing dir update", err)
	}

	audResp := aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: dirId,
		StartEpoch:     uint64(dir.LatestSTR().Epoch),
		EndEpoch:       uint64(dir.LatestSTR().Epoch)})
	if err := cLook1.CheckEquivocation(audResp); err != nil {
		t.Fatal("Client and auditor had inconsistent views", err)
	}
	// cLook2 talks to the auditor with dir history here.
	if err := cLook2.CheckEquivocation(audResp); err != nil {
		t.Fatal("Client and auditor had inconsistent views", err)
	}

	retKey1 := lookupAndVerify(t, dir, cLook1, uname1)
	// Even though cLook2 does a lookup of the old dirFork,
	// the check still passes bc it doesn't measure freshness.
	retKey2 := lookupAndVerify(t, dirFork, cLook2, uname1)
	t.Log("bad: cLook2 should detect that it's getting old state here")
	if bytes.Equal(retKey1, retKey2) {
		t.Fatal("Keys are NOT supposed to match here, even though they do")
	}
}

func TestForkGood(t *testing.T) {
	dir, dirPk := directory.NewTestDirectory(t, true)
	dirFork, err := dir.Fork()
	if err != nil {
		t.Fatal("Could not fork", err)
	}
	aud, dirId := newAuditor(t, dir, dirPk)
	cReg1 := client.New(dir.LatestSTR(), true, dirPk)
	cReg2 := client.New(dir.LatestSTR(), true, dirPk)
	cLook1 := client.New(dir.LatestSTR(), true, dirPk)
	cLook2 := client.New(dir.LatestSTR(), true, dirPk)

	// dir and dirFork see different registrations.
	registerAndVerify(t, dir, cReg1, uname1, key1)
	dir.Update()
	registerAndVerify(t, dirFork, cReg2, uname1, key2)
	dirFork.Update()

    // cLook2 is shown dirFork.
	retKey1 := lookupAndVerify(t, dir, cLook1, uname1)
	retKey2 := lookupAndVerify(t, dirFork, cLook2, uname1)

	newSTRs := protocol.NewSTRHistoryRange([]*protocol.DirSTR{dir.LatestSTR()})
	if err := aud.AuditId(dirId, newSTRs); err != nil {
		t.Fatal("Error auditing dir update", err)
	}

	audResp := aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: dirId,
		StartEpoch:     uint64(dir.LatestSTR().Epoch),
		EndEpoch:       uint64(dir.LatestSTR().Epoch)})
	if err := cLook1.CheckEquivocation(audResp); err != nil {
		t.Fatal("Client and auditor had inconsistent views", err)
	}
	// cLook2 contacts an auditor who's on a different fork.
	if err := cLook2.CheckEquivocation(audResp); err == nil {
		t.Fatal("Client supposed to detect inconsistency with auditor")
	}

	if bytes.Equal(retKey1, retKey2) {
		t.Fatal("Keys are NOT supposed to match here, even though they do")
	}
}
