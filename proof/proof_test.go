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
	Depth     int        `json:"depth"`
	Nodes     [][]string `json:"nodes,nomitempty"`
	Prefix    string     `json:"prefix,omitempty"`
	Left      string     `json:"left,omitempty"`
	Right     string     `json:"right,omitempty"`
	Value     string     `json:"value,omitempty"`
	Key       string     `json:"key,omitempty"`
	Hash      string     `json:"hash,omitempty"`
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

func TestProofVerify(t *testing.T) {
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

		var root UrkelHash
		var key UrkelHash

		if root, err = readHash(tp.Root); err != nil {
			t.Errorf("readHash failed: %s", err)
		}

		if key, err = readHash(tp.Key); err != nil {
			t.Errorf("readHash failed: %s", err)
		}

		code, _ := proof.Verify(root, key)

		if code != ProofOk {
			t.Errorf("Verify failed")
		}
	}
}

func TestJSONSerialize(t *testing.T) {
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

		proofJSON, err := json.MarshalIndent(proof, "", "  ")

		if err != nil {
			t.Errorf("json.Marshal failed: %s", err)
		}

		originalJSON, err := json.MarshalIndent(tp.Json, "", "  ")

		if err != nil {
			t.Errorf("json.Marshal failed: %s", err)
		}

		if bytes.Compare(proofJSON, originalJSON) != 0 {
			t.Errorf("JSON mismatch: %s != %s", string(proofJSON), string(originalJSON))
		}
	}
}

func TestJSONDeserialize(t *testing.T) {
	for _, tp := range testProofs {
		var err error
		var testJSON []byte

		testJSON, err = json.MarshalIndent(tp.Json, "", "  ")

		if err != nil {
			t.Errorf("json.Marshal failed: %s", err)
		}

		proof := New()

		if err = json.Unmarshal(testJSON, proof); err != nil {
			t.Errorf("json.Unmarshal failed: %s", err)
		}

		proofJSON, err := json.MarshalIndent(proof, "", "  ")

		if err != nil {
			t.Errorf("json.Marshal failed: %s", err)
		}

		if bytes.Compare(testJSON, proofJSON) != 0 {
			t.Errorf("JSON mismatch: %s != %s", string(proofJSON), string(testJSON))
		}

		proof2, err := NewFromJSON(testJSON)

		if err != nil {
			t.Errorf("NewFromJSON failed: %s", err)
		}

		proofJSON2, err := json.MarshalIndent(proof2, "", "  ")

		if err != nil {
			t.Errorf("json.Marshal failed: %s", err)
		}

		if bytes.Compare(testJSON, proofJSON2) != 0 {
			t.Errorf("JSON mismatch: %s != %s", string(proofJSON2), string(testJSON))
		}
	}
}

func TestReserializeFromJSON(t *testing.T) {
	for _, tp := range testProofs {
		var err error
		var testJSON []byte
		var raw []byte
		var serialized bytes.Buffer
		var proof *Proof

		if raw, err = hex.DecodeString(tp.Raw); err != nil {
			t.Errorf("hex.Decode failed: %s", err)
		}

		testJSON, err = json.MarshalIndent(tp.Json, "", "  ")

		if err != nil {
			t.Errorf("json.Marshal failed: %s", err)
		}

		proof, err = NewFromJSON(testJSON)

		if err != nil {
			t.Errorf("NewFromJSON failed: %s", err)
		}

		proofJSON, err := json.MarshalIndent(proof, "", "  ")

		if err != nil {
			t.Errorf("json.Marshal failed: %s", err)
		}

		if bytes.Compare(testJSON, proofJSON) != 0 {
			t.Errorf("JSON mismatch: %s != %s", string(proofJSON), string(testJSON))
		}

		err = proof.Serialize(&serialized)

		if err != nil {
			t.Errorf("Serialize failed: %s", err)
		}

		if bytes.Compare(serialized.Bytes(), raw) != 0 {
			t.Errorf("Serialize mismatch: %s != %s", hex.EncodeToString(serialized.Bytes()), tp.Raw)
		}
	}
}

func readHash(hexstr string) (hash UrkelHash, err error) {
	var raw []byte

	if raw, err = hex.DecodeString(hexstr); err != nil {
		return
	}

	copy(hash[:], raw)
	return
}
