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
			"code":    []byte("sendTo(000000000000000000000000000000, 10)"),
			"trigger": []byte(""),
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

	tB, _ = json.Marshal(t)
	log.Print(string(tB))
	log.Println("=======================")
	log.Printf("Size: %d bytes\n", len(tB))
}

type transaction struct {
	Addr             []byte                 `json:"address"`
	PrevAddr         []byte                 `json:"previous_address"`
	TxType           int                    `json:"type"`
	Data             map[string]interface{} `json:"data"`
	Timestamp        time.Time              `json:"timestamp"`
	PubKey           []byte                 `json:"public_key"`
	Sig              []byte                 `json:"signature"`
	OriginSig        []byte                 `json:"origin_signature"`
	MasterValdiation masterValidation       `json:"master_validation_stamp"`
	CrossValidations []validation           `json:"cross_validation_stamps"`
}

type validation struct {
	Status    int       `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	NodePubk  []byte    `json:"node_public_key"`
	NodeSig   []byte    `json:"node_signature"`
}

type masterValidation struct {
	PrevValidNodes  [][]byte     `json:"previous_validation-nodes"`
	Pow             []byte       `json:"proof_of_work"`
	Validation      validation   `json:"validation_stamp"`
	WHeaders        []nodeHeader `json:"welcome_headers"`
	VHeaders        []nodeHeader `json:"validation_headers"`
	SHeaders        []nodeHeader `json:"storage_headers"`
	TransactionHash []byte       `json:"transaction_hash"`
}

type nodeHeader struct {
	PubKey        []byte `json:"public_key"`
	IsUnreachable bool   `json:"is_unreachable"`
	IsMaster      bool   `json:"is_master"`
	PatchNumber   int    `json:"patch_number"`
	IsOK          bool   `json:"is_ok"`
}
