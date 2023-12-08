package proof

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

type jsonProof struct {
	ProofType string     `json:"type"`
	Depth     uint       `json:"depth"`
	Nodes     [][]string `json:"nodes"`
	Prefix    string     `json:"prefix"`
	Left      string     `json:"left"`
	Right     string     `json:"right"`
	Value     string
	Key       string
	Hash      string
}

type testProof struct {
	ProofType ProofType `json:"type"`
	Raw       string    `json:"raw"`
	Json      jsonProof `json:"json"`
	Root      string
	Key       string
}

var testProofs []testProof = nil

func init() {
	path := "testdata/proofs.json"
	testProofs = make([]testProof, 0)

	// read file
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	// parse json
	err = json.Unmarshal(data, &testProofs)
	if err != nil {
		panic(err)
	}
}

func TestProofDecode(t *testing.T) {
	for _, tp := range testProofs {
		var proof *Proof
		var raw []byte
		var err error

		if raw, err = hex.DecodeString(tp.Raw); err != nil {
			t.Errorf("hex.Decode failed: %s", err)
		}

		if proof, err = NewFromBytes(raw); err != nil {
			t.Errorf("NewFromBytes failed: %s", err)
		}

		if proof.ptype != tp.ProofType {
			t.Errorf("ProofType mismatch: %d != %d", proof.ptype, tp.ProofType)
		}

		if proof.depth != tp.Json.Depth {
			t.Errorf("Depth mismatch: %d != %d", proof.depth, tp.Json.Depth)
		}

		if len(proof.nodes) != len(tp.Json.Nodes) {
			t.Errorf("NodesLen mismatch: %d != %d", len(proof.nodes), len(tp.Json.Nodes))
		}

		if proof.IsSane() == false {
			t.Errorf("IsSane failed")
		}

		for i, node := range proof.nodes {
			jsonNode := tp.Json.Nodes[i]
			hashHex := hex.EncodeToString(node.hash[:])

			if hashHex != jsonNode[1] {
				t.Errorf("Node hash mismatch: '%s' != '%s'", hashHex, jsonNode[1])
			}

			if len(jsonNode[0]) != node.prefix.size {
				t.Errorf("Size mismatch: %d != %d", len(jsonNode[0]), node.prefix.size)
			}
		}

		switch proof.Type() {
		case ProofTypeExists:
			valueHex := hex.EncodeToString(proof.Value())

			if valueHex != tp.Json.Value {
				t.Errorf("Value mismatch: '%s' != '%s'", valueHex, tp.Json.Value)
			}
		case ProofTypeShort:
			leftHex := hex.EncodeToString(proof.left[:])
			rightHex := hex.EncodeToString(proof.right[:])

			if leftHex != tp.Json.Left {
				t.Errorf("Left hash mismatch: '%s' != '%s'", leftHex, tp.Json.Left)
			}

			if rightHex != tp.Json.Right {
				t.Errorf("Right hash mismatch: '%s' != '%s'", rightHex, tp.Json.Right)
			}

			if proof.prefix.size != len(tp.Json.Prefix) {
				t.Errorf("Proof prefix mismatch: %d != %d", proof.prefix.size, len(tp.Json.Prefix))
			}
		case ProofTypeCollision:
			keyHex := hex.EncodeToString(proof.key[:])
			hashHex := hex.EncodeToString(proof.hash[:])

			if keyHex != tp.Json.Key {
				t.Errorf("Key hash mismatch: '%s' != '%s'", keyHex, tp.Json.Key)
			}

			if hashHex != tp.Json.Hash {
				t.Errorf("Collision hash mismatch: '%s' != '%s'", hashHex, tp.Json.Hash)
			}
		}
	}
}

func TestProofReencode(t *testing.T) {
	for _, tp := range testProofs {
		var proof *Proof
		var raw []byte
		var encoded bytes.Buffer
		var err error

		if raw, err = hex.DecodeString(tp.Raw); err != nil {
			t.Errorf("hex.Decode failed: %s", err)
		}

		if proof, err = NewFromBytes(raw); err != nil {
			t.Errorf("NewFromBytes failed: %s", err)
		}

		err = proof.Serialize(&encoded)

		if err != nil {
			t.Errorf("Encode failed: %s", err)
		}

		if bytes.Compare(encoded.Bytes(), raw) != 0 {
			t.Errorf("Encode mismatch: %s != %s", hex.EncodeToString(encoded.Bytes()), tp.Raw)
		}
	}
}
