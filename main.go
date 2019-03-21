package main

import (
	"bytes"
	"compress/gzip"
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
		Timestamp:  time.Now(),
		PrevPubKey: pub,
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

	log.Printf("Transaction + validations + headers: %d bytes\n", transactionSizeWithMaster(t))
	log.Printf("Transaction + validations + without headers : %d bytes\n", transactionSizeWithoutHeaders(t))
	log.Printf("Transaction + validations + compress custom encoding headers: %d bytes\n", transactionSizeWithCustomCompHeaders(t))
	log.Printf("Transaction + validations + compress JSON encoding headers: %d bytes\n", transactionSizeWithJSONCompHeaders(t))
	log.Printf("Transaction only: %d bytes\n", transactionSizeOnly(t))
}

func transactionSizeOnly(t transaction) int {
	prop := t.Data["proposal_shared_origin_key"].(map[string][]byte)

	return len(t.Addr) +
		1 + //Type
		10 + //Timestamp
		len(t.Data["code"].([]byte)) +
		len(prop["public_key"]) +
		len(prop["encrypted_private_key"]) +
		len(t.PrevPubKey) +
		len(t.Sig) +
		len(t.OriginSig)
}

func transactionSizeWithMaster(t transaction) int {

	var vSize int
	for _, v := range t.CrossValidations {
		vSize += validationSize(v)
	}

	return transactionSizeOnly(t) + masterValidationSize(t.MasterValdiation) + vSize
}

func transactionSizeWithoutHeaders(t transaction) int {
	var vSize int
	for _, v := range t.CrossValidations {
		vSize += validationSize(v)
	}

	return transactionSizeOnly(t) + masterValidationWithoutHeaders(t.MasterValdiation) + vSize
}

func transactionSizeWithCustomCompHeaders(t transaction) int {
	var vSize int
	for _, v := range t.CrossValidations {
		vSize += validationSize(v)
	}

	return transactionSizeOnly(t) + masterValidationWithCustomCompressedHeaders(t.MasterValdiation) + vSize
}

func transactionSizeWithJSONCompHeaders(t transaction) int {
	var vSize int
	for _, v := range t.CrossValidations {
		vSize += validationSize(v)
	}

	return transactionSizeOnly(t) + masterValidationWithJSONCompressedHeaders(t.MasterValdiation) + vSize
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

func masterValidationWithoutHeaders(v masterValidation) int {
	return len(v.Pow) +
		len(v.PrevValidNodes) +
		len(v.TransactionHash) +
		validationSize(v.Validation)
}

func masterValidationWithCustomCompressedHeaders(v masterValidation) int {
	wHeaderSize := customCompressHeaders(v.WHeaders)
	vHeaderSize := customCompressHeaders(v.VHeaders)
	sHeaderSize := customCompressHeaders(v.SHeaders)

	return len(v.Pow) +
		len(v.PrevValidNodes) +
		len(v.TransactionHash) +
		wHeaderSize + vHeaderSize + sHeaderSize +
		validationSize(v.Validation)
}

func masterValidationWithJSONCompressedHeaders(v masterValidation) int {
	wHeaderSize := jsonCompressHeaders(v.WHeaders)
	vHeaderSize := jsonCompressHeaders(v.VHeaders)
	sHeaderSize := jsonCompressHeaders(v.SHeaders)

	return len(v.Pow) +
		len(v.PrevValidNodes) +
		len(v.TransactionHash) +
		wHeaderSize + vHeaderSize + sHeaderSize +
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
	PrevPubKey       []byte
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

func compress(data []byte) []byte {
	var buf bytes.Buffer
	g := gzip.NewWriter(&buf)
	g.Write(data)
	g.Flush()
	g.Close()
	return buf.Bytes()
}

func customCompressHeaders(hh []nodeHeader) int {
	b := make([]byte, 0)
	for _, h := range hh {
		b = append(b, h.PubKey...)
		if h.IsUnreachable {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
		if h.IsOK {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
		if h.IsMaster {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
		b = append(b, byte(h.PatchNumber))
	}
	return len(compress(b))
}

func jsonCompressHeaders(hh []nodeHeader) int {
	b := make([]byte, 0)
	for _, h := range hh {
		j, _ := json.Marshal(h)
		b = append(b, j...)
	}
	return len(compress(b))
}
