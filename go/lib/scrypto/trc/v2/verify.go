// Copyright 2019 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trc

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto"
)

const (
	// DecodeProtectedFailed indicates the signatrue metadata fails to decode.
	DecodeProtectedFailed = "unable to decode protected signature metadata"
	// UnexpectedVoteSignature indicates an unexpected voting signature.
	UnexpectedVoteSignature = "unexpected vote signature"
	// UnexpectedPOPSignature indicates an unexpected proof of possession signature.
	UnexpectedPOPSignature = "unexpected proof of possession signature"
	// InvalidProtected indicates that the protected signature metadata is invalid.
	InvalidProtected = "invalid protected signature metadata"
	// MissingVoteSignature indicates a voting signature of an AS is missing.
	MissingVoteSignature = "missing vote signature"
	// MissingPOPSignature indicates a missing proof of possession signature.
	MissingPOPSignature = "missing proof of possession signature"
	// VoteVerificationError indicates the signature verification of a vote failed.
	VoteVerificationError = "vote signature verification error"
	// POPVerificationError indicates the signature verification of a proof of possession failed.
	POPVerificationError = "proof of possession signature verification error"
	// DuplicateVoteSignature indicates a duplicate voting signature for the same AS.
	DuplicateVoteSignature = "duplicate vote signature"
	// DuplicatePOPSignature indicates a duplicate proof of possession signature
	// for the same AS and key type.
	DuplicatePOPSignature = "duplicate proof of possession signature"
)

// Votes maps ASes to their decoded vote.
type Votes map[addr.AS]DecodedSignature

// POPs maps ASes to their decoded proof of possession.
type POPs map[addr.AS]map[KeyType]DecodedSignature

// UpdateVerifier verifies a signed TRC update. The caller must first use the
// UpdateValidator to check the update validity. UpdateVerifier simply checks
// that the signatures are verifiable (including the proof of possession).
type UpdateVerifier struct {
	// Prev is the previous TRC. Its version must be Next.Version - 1.
	Prev *TRC
	// Next is the updated TRC.
	Next *TRC
	// NextEncoded is the encoded next TRC used for signature input.
	NextEncoded Encoded
	// Signatures contains all signatures attached to the new TRC.
	Signatures []Signature
}

// Verify checks that all signatures mentioned in the next TRC are present and
// verifiable, and that no others are attached.
func (v UpdateVerifier) Verify() error {
	votes, pops, err := decodeSignatures(v.Signatures)
	if err != nil {
		return common.NewBasicError(DecodeProtectedFailed, err)
	}
	pv := popVerifier{
		TRC:        v.Next,
		Encoded:    v.NextEncoded,
		signatures: pops,
	}
	if err := v.checkVotes(votes); err != nil {
		return err
	}
	if err := pv.check(); err != nil {
		return err
	}
	if err := v.verifyVotes(votes); err != nil {
		return err
	}
	if err := pv.verify(); err != nil {
		return err
	}
	return nil
}

func (v UpdateVerifier) checkVotes(votes Votes) error {
	for as, sig := range votes {
		vote, ok := v.Next.Votes[as]
		if !ok {
			return common.NewBasicError(UnexpectedVoteSignature, nil, "as", as)
		}
		expected := Protected{
			Algorithm:  v.Prev.PrimaryASes[as].Keys[vote.KeyType].Algorithm,
			Type:       VoteSignature,
			KeyType:    vote.KeyType,
			KeyVersion: vote.KeyVersion,
			AS:         as,
		}
		if sig.Protected != expected {
			return common.NewBasicError(InvalidProtected, nil,
				"expected", expected, "actual", sig.Protected)
		}
	}
	for as := range v.Next.Votes {
		if _, ok := votes[as]; !ok {
			return common.NewBasicError(MissingVoteSignature, nil, "as", as)
		}
	}
	return nil
}

func (v UpdateVerifier) verifyVotes(votes Votes) error {
	for as, sig := range votes {
		meta := v.Prev.PrimaryASes[as].Keys[sig.Protected.KeyType]
		input := SigInput(sig.EncodedProtected, v.NextEncoded)
		if err := scrypto.Verify(input, sig.Signature, meta.Key, meta.Algorithm); err != nil {
			return common.NewBasicError(VoteVerificationError, err, "as", as, "meta", meta)
		}
	}
	return nil
}

// POPVerifier verifies the proof of possession signature on a TRC. The caller
// must make sure the TRC is validate, POPVerifier simply checks that the
// signatures are verifiable.
type POPVerifier struct {
	// TRC holds the TRC to be verified.
	TRC *TRC
	// NextEncoded is the encoded next TRC used for signature input.
	Encoded Encoded
	// Signatures contains all signatures attached to the new TRC.
	Signatures []Signature
}

// Verify checks that all proof of possession signatures mentioned in the TRC are
// present and verifiable, and that no others are attached.
func (v POPVerifier) Verify() error {
	_, pops, err := decodeSignatures(v.Signatures)
	if err != nil {
		return common.NewBasicError(DecodeProtectedFailed, err)
	}
	pv := popVerifier{
		TRC:        v.TRC,
		Encoded:    v.Encoded,
		signatures: pops,
	}
	if err := pv.check(); err != nil {
		return err
	}
	if err := pv.verify(); err != nil {
		return err
	}
	return nil
}

type popVerifier struct {
	TRC        *TRC
	Encoded    Encoded
	signatures POPs
}

func (v *popVerifier) check() error {
	for as, pops := range v.signatures {
		for _, sig := range pops {
			if !containsKeyType(sig.Protected.KeyType, v.TRC.ProofOfPossession[as]) {
				return common.NewBasicError(UnexpectedPOPSignature, nil,
					"as", as, "key_type", sig.Protected.KeyType)
			}
			meta := v.TRC.PrimaryASes[as].Keys[sig.Protected.KeyType]
			expected := Protected{
				Algorithm:  meta.Algorithm,
				Type:       POPSignature,
				KeyType:    sig.Protected.KeyType,
				KeyVersion: meta.KeyVersion,
				AS:         as,
			}
			if sig.Protected != expected {
				return common.NewBasicError(InvalidProtected, nil,
					"expected", expected, "actual", sig.Protected)
			}
		}
	}
	for as, keyTypes := range v.TRC.ProofOfPossession {
		for _, keyType := range keyTypes {
			if _, ok := v.signatures[as][keyType]; !ok {
				return common.NewBasicError(MissingPOPSignature, nil, "as", as, "key_type", keyType)
			}
		}
	}
	return nil
}

func (v *popVerifier) verify() error {
	for as, pops := range v.signatures {
		for keyType, sig := range pops {
			meta := v.TRC.PrimaryASes[as].Keys[keyType]
			input := SigInput(sig.EncodedProtected, v.Encoded)
			if err := scrypto.Verify(input, sig.Signature, meta.Key, meta.Algorithm); err != nil {
				return common.NewBasicError(POPVerificationError, err,
					"as", as, "key_type", keyType)
			}
		}
	}
	return nil
}

// DecodedSignature holds the signature with the decoded protected meta data.
type DecodedSignature struct {
	EncodedProtected EncodedProtected
	Protected        Protected
	Signature        []byte
}

func decodeSignatures(signatures []Signature) (Votes, POPs, error) {
	votes := make(Votes)
	pops := make(POPs)
	sigs := make([]DecodedSignature, 0, len(signatures))
	for _, sig := range signatures {
		prot, err := sig.EncodedProtected.Decode()
		if err != nil {
			return nil, nil, err
		}
		sigs = append(sigs, DecodedSignature{
			EncodedProtected: sig.EncodedProtected,
			Protected:        prot,
			Signature:        sig.Signature,
		})
	}
	for _, sig := range sigs {
		switch sig.Protected.Type {
		case VoteSignature:
			if _, ok := votes[sig.Protected.AS]; ok {
				return nil, nil, common.NewBasicError(DuplicateVoteSignature, nil,
					"as", sig.Protected.AS)
			}
			votes[sig.Protected.AS] = sig
		case POPSignature:
			if _, ok := pops[sig.Protected.AS][sig.Protected.KeyType]; ok {
				return nil, nil, common.NewBasicError(DuplicatePOPSignature, nil,
					"as", sig.Protected.AS, "key_type", sig.Protected.KeyType)
			}
			if _, ok := pops[sig.Protected.AS]; !ok {
				pops[sig.Protected.AS] = make(map[KeyType]DecodedSignature)
			}
			pops[sig.Protected.AS][sig.Protected.KeyType] = sig
		}
	}
	return votes, pops, nil
}

func containsKeyType(keyType KeyType, keyTypes []KeyType) bool {
	for _, t := range keyTypes {
		if t == keyType {
			return true
		}
	}
	return false
}
