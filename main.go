package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"log"
	"time"

	"golang.org/x/crypto/ed25519"
)

func main() {

	pub, pv, _ := ed25519.GenerateKey(rand.Reader)

	hash := sha256.New()
	hash.Write(pub)
	addr := hash.Sum(nil)
	hash.Reset()

	hash.Write(pv)
	hash.Write(pv)

	t := transaction{
		Addr:   addr,
		TxType: 1,
		Data: map[string]interface{}{
			"code": []byte("sendTo(000000000000000000000000000000, 10)"),
			"proposal_shared_origin_key": map[string][]byte{
				"public_key":            pub,
				"encrypted_private_key": hash.Sum(nil),
			},
		},
		Timestamp: time.Now(),
		PubKey:    pub,
	}

	hash.Reset()

	tB, _ := json.Marshal(t)
	hash.Write(tB)
	sig := ed25519.Sign(pv, tB)
	t.Sig = sig
	t.OriginSig = sig

	mvB, _ := json.Marshal(validation{
		Status:    1,
		Timestamp: time.Now(),
		NodePubk:  pub,
	})
	mvSig := ed25519.Sign(pv, mvB)

	wHeaders := make([]nodeHeader, 5)
	for i := 0; i < 5; i++ {
		wHeaders[i] = nodeHeader{
			PubKey:        pub,
			IsUnreachable: false,
			IsOK:          true,
			IsMaster:      true,
			PatchNumber:   1,
		}
	}

	vHeaders := make([]nodeHeader, 5) //4 salves + 1 master
	for i := 0; i < 4; i++ {
		vHeaders[i] = nodeHeader{
			PubKey:        pub,
			IsUnreachable: false,
			IsOK:          true,
			IsMaster:      false,
			PatchNumber:   1,
		}

		v := validation{
			Status:    1,
			Timestamp: time.Now(),
			NodePubk:  pub,
		}
		vB, _ := json.Marshal(v)
		vSig := ed25519.Sign(pv, vB)
		v.NodeSig = vSig

		t.CrossValidations = append(t.CrossValidations, v)
	}
	vHeaders[4] = nodeHeader{
		PubKey:        pub,
		IsUnreachable: false,
		IsOK:          true,
		IsMaster:      true,
		PatchNumber:   1,
	}

	sHeaders := make([]nodeHeader, 36)
	for i := 0; i < 36; i++ {
		sHeaders[i] = nodeHeader{
			PubKey:        pub,
			IsUnreachable: false,
			IsOK:          true,
			IsMaster:      true,
			PatchNumber:   1,
		}
	}

	mv := masterValidation{
		PrevValidNodes: nil,
		Pow:            pub,
		Validation: validation{
			Status:    1,
			Timestamp: time.Now(),
			NodePubk:  pub,
			NodeSig:   mvSig,
		},
		WHeaders:        wHeaders,
		VHeaders:        vHeaders,
		SHeaders:        sHeaders,
		TransactionHash: hash.Sum(nil),
	}

	t.MasterValdiation = mv

	log.Println("=======================")
	log.Printf("Size: %d bytes\n", transactionSize(t))
}

func transactionSize(t transaction) int {

	var vSize int
	for _, v := range t.CrossValidations {
		vSize += validationSize(v)
	}

	prop := t.Data["proposal_shared_origin_key"].(map[string][]byte)

	return len(t.Addr) +
		1 + //Type
		10 + //Timestamp
		len(t.Data["code"].([]byte)) +
		len(prop["public_key"]) +
		len(prop["encrypted_private_key"]) +
		len(t.PubKey) +
		len(t.Sig) +
		len(t.OriginSig) +
		masterValidationSize(t.MasterValdiation) + vSize
}

func validationSize(v validation) int {
	return len(v.NodePubk) +
		len(v.NodeSig) +
		1 + //Status
		10 //Timestamp
}

func masterValidationSize(v masterValidation) int {

	var wHeaderSize, vHeaderSize, sHeaderSize int

	for _, h := range v.WHeaders {
		wHeaderSize += headerSize(h)
	}

	for _, h := range v.VHeaders {
		vHeaderSize += headerSize(h)
	}

	for _, h := range v.SHeaders {
		sHeaderSize += headerSize(h)
	}

	return len(v.Pow) +
		len(v.PrevValidNodes) +
		wHeaderSize + vHeaderSize + sHeaderSize +
		len(v.TransactionHash) +
		validationSize(v.Validation)
}

func headerSize(h nodeHeader) int {
	return 1 + //isMaster
		1 + //isUnreachable
		1 + //IsOk
		len(h.PubKey) +
		3 //Patch number
}

type transaction struct {
	Addr             []byte
	TxType           int
	Data             map[string]interface{}
	Timestamp        time.Time
	PubKey           []byte
	Sig              []byte
	OriginSig        []byte
	MasterValdiation masterValidation
	CrossValidations []validation
}

type validation struct {
	Status    int
	Timestamp time.Time
	NodePubk  []byte
	NodeSig   []byte
}

type masterValidation struct {
	PrevValidNodes  [][]byte
	Pow             []byte
	Validation      validation
	WHeaders        []nodeHeader
	VHeaders        []nodeHeader
	SHeaders        []nodeHeader
	TransactionHash []byte
}

type nodeHeader struct {
	PubKey        []byte
	IsUnreachable bool
	IsMaster      bool
	PatchNumber   int
	IsOK          bool
}
