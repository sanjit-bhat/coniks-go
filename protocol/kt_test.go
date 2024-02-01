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

	retKey1 := lookupAndVerify(t, dir, cLook1, uname1)
	retKey2 := lookupAndVerify(t, dir, cLook2, uname1)
	if !bytes.Equal(retKey1, retKey2) {
		t.Fatal("Key mismatch")
	}

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
	if err := cLook2.CheckEquivocation(audResp); err != nil {
		t.Fatal("Client and auditor had inconsistent views", err)
	}
}
