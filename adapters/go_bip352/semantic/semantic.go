package semantic

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	bip352 "github.com/setavenger/go-bip352"
)

const (
	SemanticWorkerAPIVersion      = 1
	semanticContractVersion       = 1
	semanticAdapterRequestVersion = 1
	caseFormatVersion             = 2
	kMax                          = 2323
)

var (
	errNoEligibleInputs = errors.New("no_eligible_inputs")
	errPointAtInfinity  = errors.New("point_at_infinity")
	errZeroScalar       = errors.New("zero_scalar")
)

type Source struct {
	UpstreamCommit string `json:"upstream_commit"`
	CaseIndex      int    `json:"case_index"`
	EntryIndex     int    `json:"entry_index"`
	Kind           string `json:"kind"`
	Comment        string `json:"comment"`
	ID             string `json:"id"`
}

type InputRequest struct {
	OutpointTxid     string   `json:"outpoint_txid"`
	OutpointVout     uint32   `json:"outpoint_vout"`
	InputType        string   `json:"input_type"`
	PrevoutScriptPub *string  `json:"prevout_script_pubkey"`
	ScriptSig        *string  `json:"script_sig"`
	Txinwitness      *string  `json:"txinwitness"`
	TxinwitnessStack []string `json:"txinwitness_stack"`
	Privkey          *string  `json:"privkey"`
	Pubkey           *string  `json:"pubkey"`
}

type RecipientGroupRequest struct {
	ScanPubkey  string `json:"scan_pubkey"`
	SpendPubkey string `json:"spend_pubkey"`
	Count       uint16 `json:"count"`
}

type ReceiverKeysRequest struct {
	ScanPrivkey  string `json:"scan_privkey"`
	SpendPrivkey string `json:"spend_privkey"`
}

type ExpectationHints struct {
	DetailedOutputsRequired *bool `json:"detailed_outputs_required"`
}

type AdapterRequest struct {
	SemanticAdapterRequestVersion uint32                  `json:"semantic_adapter_request_version"`
	CaseFormatVersion             uint32                  `json:"case_format_version"`
	Kind                          string                  `json:"kind"`
	Network                       string                  `json:"network"`
	SilentPaymentVersion          uint8                   `json:"silent_payment_version"`
	Seed                          uint64                  `json:"seed"`
	Flags                         uint32                  `json:"flags"`
	Source                        Source                  `json:"source"`
	Inputs                        []InputRequest          `json:"inputs"`
	ExpectationHints              *ExpectationHints       `json:"expectation_hints"`
	RecipientGroups               []RecipientGroupRequest `json:"recipient_groups"`
	OutputsToScan                 []string                `json:"outputs_to_scan"`
	ReceiverKeys                  *ReceiverKeysRequest    `json:"receiver_keys"`
	Labels                        []uint32                `json:"labels"`
}

type SharedSecretEntry struct {
	ScanPubkey   string  `json:"scan_pubkey"`
	SharedSecret *string `json:"shared_secret"`
}

type FoundOutput struct {
	PubKey       string `json:"pub_key"`
	PrivKeyTweak string `json:"priv_key_tweak"`
}

type scanGroup struct {
	scanPubkeyHex string
	scanPubkey    [33]byte
	spendPubkeys  [][33]byte
	limitExceeded bool
}

type eligibleSendInput struct {
	pubkey    [33]byte
	secretKey [32]byte
	isTaproot bool
}

type eligibleReceiveInput struct {
	pubkey [33]byte
}

type receiverBundle struct {
	addresses    []string
	scanPrivkey  [32]byte
	scanPubkey   [33]byte
	spendPrivkey [32]byte
	spendPubkey  [33]byte
}

func RunRequestJSON(input string) (output string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
			output = ""
		}
	}()

	var request AdapterRequest
	if err := json.Unmarshal([]byte(input), &request); err != nil {
		return "", fmt.Errorf("invalid request JSON: %w", err)
	}
	if err := validateRequest(&request); err != nil {
		return "", err
	}

	var response map[string]any
	switch request.Kind {
	case "send":
		response, err = deriveSendSemantics(&request)
	case "receive":
		response, err = deriveReceiveSemantics(&request)
	default:
		err = fmt.Errorf("unknown kind")
	}
	if err != nil {
		return "", err
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func validateRequest(request *AdapterRequest) error {
	if request.SemanticAdapterRequestVersion != semanticAdapterRequestVersion {
		return fmt.Errorf("unsupported semantic adapter request version")
	}
	if request.CaseFormatVersion != caseFormatVersion {
		return fmt.Errorf("case_format_version must be 2")
	}
	if request.SilentPaymentVersion != 0 {
		return fmt.Errorf("silent_payment_version must be 0")
	}
	if request.Kind != "send" && request.Kind != "receive" {
		return fmt.Errorf("unknown kind")
	}
	if request.Source.Kind != request.Kind {
		return fmt.Errorf("source.kind mismatch")
	}
	switch request.Network {
	case "mainnet", "testnet", "regtest":
	default:
		return fmt.Errorf("unsupported network: %s", request.Network)
	}
	if request.Kind == "send" && len(request.RecipientGroups) == 0 {
		return fmt.Errorf("missing recipient_groups")
	}
	if request.Kind == "receive" {
		if request.ReceiverKeys == nil {
			return fmt.Errorf("missing receiver_keys")
		}
		if request.Labels == nil {
			return fmt.Errorf("missing labels")
		}
		if request.OutputsToScan == nil {
			return fmt.Errorf("missing outputs_to_scan")
		}
	}
	return nil
}

func deriveSendSemantics(request *AdapterRequest) (map[string]any, error) {
	vins, err := buildVins(request)
	if err != nil {
		return nil, err
	}
	groups, err := buildScanGroups(request.RecipientGroups)
	if err != nil {
		return nil, err
	}

	eligible, inputPubkeys, err := collectSendInputs(vins)
	if err != nil {
		return nil, err
	}
	emptySharedSecrets := buildEmptySharedSecrets(groups)

	payload := map[string]any{
		"semantic_contract_version": semanticContractVersion,
		"case_format_version":       caseFormatVersion,
		"kind":                      "send",
		"source":                    request.Source,
		"semantic_status":           "ok",
		"input_pubkeys":             inputPubkeys,
		"input_hash":                nil,
		"input_private_key_sum":     nil,
		"sender_shared_secrets":     emptySharedSecrets,
		"acceptable_output_sets":    [][]string{{}},
		"output_count_options":      []int{0},
		"notes":                     []string{},
	}

	if len(eligible) == 0 {
		payload["semantic_status"] = "no_eligible_inputs"
		return payload, nil
	}

	aSum, err := sumInputSecretKeys(eligible)
	switch {
	case errors.Is(err, errZeroScalar):
		payload["semantic_status"] = "zero_scalar"
		payload["input_private_key_sum"] = hex.EncodeToString(aSum[:])
		return payload, nil
	case err != nil:
		return nil, err
	}
	payload["input_private_key_sum"] = hex.EncodeToString(aSum[:])

	_, aSumPubkeyRaw := btcec.PrivKeyFromBytes(aSum[:])
	var aSumPubkey [33]byte
	copy(aSumPubkey[:], aSumPubkeyRaw.SerializeCompressed())
	inputHash, err := bip352.ComputeInputHash(vins, aSumPubkey)
	if err != nil {
		return nil, err
	}
	payload["input_hash"] = hex.EncodeToString(inputHash[:])

	if scanGroupRecipientLimitExceeded(groups) {
		payload["semantic_status"] = "recipient_limit_exceeded"
		payload["notes"] = []string{"per_group_recipient_limit_exceeded"}
		return payload, nil
	}

	sharedSecrets, err := buildSenderSharedSecrets(groups, aSum, inputHash)
	if err != nil {
		return nil, err
	}
	outputSet, err := deriveSenderOutputs(groups, aSum, inputHash)
	if err != nil {
		return nil, err
	}

	payload["sender_shared_secrets"] = sharedSecrets
	payload["acceptable_output_sets"] = [][]string{outputSet}
	payload["output_count_options"] = []int{len(outputSet)}
	return payload, nil
}

func deriveReceiveSemantics(request *AdapterRequest) (map[string]any, error) {
	vins, err := buildVins(request)
	if err != nil {
		return nil, err
	}
	eligible, inputPubkeys, err := collectReceiveInputs(vins)
	if err != nil {
		return nil, err
	}
	receiver, err := buildReceiverBundle(request.Network, request.ReceiverKeys, request.Labels)
	if err != nil {
		return nil, err
	}

	detailedOutputsRequired := true
	if request.ExpectationHints != nil && request.ExpectationHints.DetailedOutputsRequired != nil {
		detailedOutputsRequired = *request.ExpectationHints.DetailedOutputsRequired
	}

	payload := map[string]any{
		"semantic_contract_version":  semanticContractVersion,
		"case_format_version":        caseFormatVersion,
		"kind":                       "receive",
		"source":                     request.Source,
		"semantic_status":            "ok",
		"input_pubkeys":              inputPubkeys,
		"input_hash":                 nil,
		"receiving_addresses":        receiver.addresses,
		"input_pubkey_sum":           nil,
		"tweak":                      nil,
		"shared_secret":              nil,
		"detailed_outputs_available": detailedOutputsRequired,
		"found_output_count":         0,
		"found_outputs":              []FoundOutput{},
		"notes":                      []string{},
	}

	if len(eligible) == 0 {
		payload["semantic_status"] = "no_eligible_inputs"
		payload["detailed_outputs_available"] = true
		return payload, nil
	}

	pubkeys := make([][33]byte, 0, len(eligible))
	for _, item := range eligible {
		pubkeys = append(pubkeys, item.pubkey)
	}
	aSum, err := sumPublicKeys(pubkeys)
	switch {
	case errors.Is(err, errPointAtInfinity):
		payload["semantic_status"] = "point_at_infinity"
		payload["detailed_outputs_available"] = true
		return payload, nil
	case err != nil:
		return nil, err
	}
	payload["input_pubkey_sum"] = hex.EncodeToString(aSum[:])

	inputHash, err := bip352.ComputeInputHash(vins, aSum)
	if err != nil {
		return nil, err
	}
	payload["input_hash"] = hex.EncodeToString(inputHash[:])

	tweak, err := deriveTweak(aSum, inputHash)
	if err != nil {
		return nil, err
	}
	payload["tweak"] = hex.EncodeToString(tweak[:])

	sharedSecret, err := deriveReceiveSharedSecret(aSum, receiver.scanPrivkey, inputHash)
	if err != nil {
		return nil, err
	}
	payload["shared_secret"] = hex.EncodeToString(sharedSecret[:])

	labels, err := buildLabels(receiver.scanPrivkey, request.Labels)
	if err != nil {
		return nil, err
	}
	outputsToScan, err := decodeOutputsToScan(request.OutputsToScan)
	if err != nil {
		return nil, err
	}
	foundOutputCount, foundOutputs, notes, err := scanOutputs(
		receiver.spendPubkey,
		labels,
		outputsToScan,
		sharedSecret,
		detailedOutputsRequired,
	)
	if err != nil {
		return nil, err
	}
	if !detailedOutputsRequired {
		payload["detailed_outputs_available"] = false
	}
	payload["found_output_count"] = foundOutputCount
	payload["found_outputs"] = foundOutputs
	payload["notes"] = notes
	return payload, nil
}

func buildVins(request *AdapterRequest) ([]*bip352.Vin, error) {
	vins := make([]*bip352.Vin, 0, len(request.Inputs))
	for _, input := range request.Inputs {
		txidBytes, err := decodeFixedHex(input.OutpointTxid, 32, "invalid outpoint_txid")
		if err != nil {
			return nil, err
		}
		scriptPubkey, err := decodeRequiredHex(input.PrevoutScriptPub, "missing prevout_script_pubkey")
		if err != nil {
			return nil, err
		}
		scriptSig, err := decodeOptionalHex(input.ScriptSig)
		if err != nil {
			return nil, err
		}
		witness, err := decodeWitnessStack(input.TxinwitnessStack)
		if err != nil {
			return nil, err
		}

		var txid [32]byte
		copy(txid[:], txidBytes)
		vin := &bip352.Vin{
			Txid:         txid,
			Vout:         input.OutpointVout,
			Amount:       100000,
			ScriptPubKey: scriptPubkey,
			ScriptSig:    scriptSig,
			Witness:      witness,
		}

		if input.Privkey != nil {
			privkeyBytes, err := decodeFixedHex(*input.Privkey, 32, "invalid privkey")
			if err != nil {
				return nil, err
			}
			var privkey [32]byte
			copy(privkey[:], privkeyBytes)
			vin.SecretKey = &privkey
		}

		vins = append(vins, vin)
	}
	return vins, nil
}

func collectSendInputs(vins []*bip352.Vin) ([]eligibleSendInput, []string, error) {
	eligible := make([]eligibleSendInput, 0, len(vins))
	inputPubkeys := make([]string, 0, len(vins))
	for _, vin := range vins {
		pubkey, isTaproot, ok, err := extractEligiblePubkey(vin)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			continue
		}
		if vin.SecretKey == nil {
			return nil, nil, fmt.Errorf("eligible sender input is missing privkey")
		}
		eligible = append(eligible, eligibleSendInput{
			pubkey:    pubkey,
			secretKey: *vin.SecretKey,
			isTaproot: isTaproot,
		})
		inputPubkeys = append(inputPubkeys, hex.EncodeToString(pubkey[:]))
	}
	return eligible, inputPubkeys, nil
}

func collectReceiveInputs(vins []*bip352.Vin) ([]eligibleReceiveInput, []string, error) {
	eligible := make([]eligibleReceiveInput, 0, len(vins))
	inputPubkeys := make([]string, 0, len(vins))
	for _, vin := range vins {
		pubkey, _, ok, err := extractEligiblePubkey(vin)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			continue
		}
		eligible = append(eligible, eligibleReceiveInput{pubkey: pubkey})
		inputPubkeys = append(inputPubkeys, hex.EncodeToString(pubkey[:]))
	}
	return eligible, inputPubkeys, nil
}

func extractEligiblePubkey(vin *bip352.Vin) ([33]byte, bool, bool, error) {
	switch {
	case isP2TR(vin.ScriptPubKey):
		if len(vin.Witness) == 0 {
			return [33]byte{}, false, false, nil
		}
		witness := vin.Witness
		if len(witness) > 1 && len(witness[len(witness)-1]) == 1 && witness[len(witness)-1][0] == 0x50 {
			witness = witness[:len(witness)-1]
		}
		if len(witness) > 1 {
			controlBlock := witness[len(witness)-1]
			if len(controlBlock) < 33 {
				return [33]byte{}, false, false, nil
			}
			if bytes.Equal(controlBlock[1:33], bip352.NumsH) {
				return [33]byte{}, false, false, nil
			}
		}
		if len(vin.ScriptPubKey) != 34 {
			return [33]byte{}, false, false, nil
		}
		var pubkey [33]byte
		pubkey[0] = 0x02
		copy(pubkey[1:], vin.ScriptPubKey[2:])
		return pubkey, true, true, nil
	case isP2WPKH(vin.ScriptPubKey):
		if len(vin.Witness) == 0 {
			return [33]byte{}, false, false, errors.New("failed to parse input pubkey: missing witness pubkey")
		}
		candidate := vin.Witness[len(vin.Witness)-1]
		if len(candidate) != 33 {
			return [33]byte{}, false, false, nil
		}
		var pubkey [33]byte
		copy(pubkey[:], candidate)
		return pubkey, false, true, nil
	case isP2PKH(vin.ScriptPubKey):
		if len(vin.ScriptSig) < 33 {
			return [33]byte{}, false, false, nil
		}
		scriptPubkeyHash := vin.ScriptPubKey[3:23]
		for offset := len(vin.ScriptSig); offset >= 33; offset-- {
			candidate := vin.ScriptSig[offset-33 : offset]
			if len(candidate) != 33 {
				continue
			}
			if !bytes.Equal(bip352.Hash160(candidate), scriptPubkeyHash) {
				continue
			}
			var pubkey [33]byte
			copy(pubkey[:], candidate)
			return pubkey, false, true, nil
		}
		return [33]byte{}, false, false, nil
	case isP2SH(vin.ScriptPubKey):
		if len(vin.ScriptSig) != 23 {
			return [33]byte{}, false, false, nil
		}
		if !bytes.Equal(vin.ScriptSig[:3], []byte{0x16, 0x00, 0x14}) {
			return [33]byte{}, false, false, nil
		}
		if len(vin.Witness) == 0 {
			return [33]byte{}, false, false, errors.New("failed to parse input pubkey: missing witness pubkey")
		}
		candidate := vin.Witness[len(vin.Witness)-1]
		if len(candidate) != 33 {
			return [33]byte{}, false, false, nil
		}
		var pubkey [33]byte
		copy(pubkey[:], candidate)
		return pubkey, false, true, nil
	default:
		return [33]byte{}, false, false, nil
	}
}

func buildScanGroups(groups []RecipientGroupRequest) ([]scanGroup, error) {
	ordered := make([]scanGroup, 0, len(groups))
	indexByScan := make(map[string]int)
	for _, group := range groups {
		scanBytes, err := decodeFixedHex(group.ScanPubkey, 33, "invalid scan_pubkey")
		if err != nil {
			return nil, err
		}
		spendBytes, err := decodeFixedHex(group.SpendPubkey, 33, "invalid spend_pubkey")
		if err != nil {
			return nil, err
		}
		var scanPubkey [33]byte
		var spendPubkey [33]byte
		copy(scanPubkey[:], scanBytes)
		copy(spendPubkey[:], spendBytes)

		index, ok := indexByScan[group.ScanPubkey]
		if !ok {
			index = len(ordered)
			ordered = append(ordered, scanGroup{
				scanPubkeyHex: group.ScanPubkey,
				scanPubkey:    scanPubkey,
				spendPubkeys:  make([][33]byte, 0),
			})
			indexByScan[group.ScanPubkey] = index
		}
		remaining := kMax - len(ordered[index].spendPubkeys)
		appendCount := int(group.Count)
		if appendCount > remaining {
			appendCount = remaining
			ordered[index].limitExceeded = true
		}
		for i := 0; i < appendCount; i++ {
			ordered[index].spendPubkeys = append(ordered[index].spendPubkeys, spendPubkey)
		}
	}
	return ordered, nil
}

func buildEmptySharedSecrets(groups []scanGroup) []SharedSecretEntry {
	entries := make([]SharedSecretEntry, 0, len(groups))
	for _, group := range groups {
		entries = append(entries, SharedSecretEntry{
			ScanPubkey:   group.scanPubkeyHex,
			SharedSecret: nil,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ScanPubkey < entries[j].ScanPubkey
	})
	return entries
}

func buildSenderSharedSecrets(groups []scanGroup, aSum [32]byte, inputHash [32]byte) ([]SharedSecretEntry, error) {
	entries := make([]SharedSecretEntry, 0, len(groups))
	for _, group := range groups {
		scanCopy := group.scanPubkey
		secretCopy := aSum
		inputHashCopy := inputHash
		sharedSecret, err := bip352.CreateSharedSecret(scanCopy, secretCopy, &inputHashCopy)
		if err != nil {
			return nil, err
		}
		secretHex := hex.EncodeToString(sharedSecret[:])
		entries = append(entries, SharedSecretEntry{
			ScanPubkey:   group.scanPubkeyHex,
			SharedSecret: &secretHex,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ScanPubkey < entries[j].ScanPubkey
	})
	return entries, nil
}

func deriveSenderOutputs(groups []scanGroup, aSum [32]byte, inputHash [32]byte) ([]string, error) {
	outputSet := make(map[string]struct{})
	for _, group := range groups {
		scanCopy := group.scanPubkey
		secretCopy := aSum
		inputHashCopy := inputHash
		sharedSecret, err := bip352.CreateSharedSecret(scanCopy, secretCopy, &inputHashCopy)
		if err != nil {
			return nil, err
		}
		for index, spendPubkey := range group.spendPubkeys {
			output, err := bip352.CreateOutputPubKey(sharedSecret, spendPubkey, uint32(index))
			if err != nil {
				return nil, err
			}
			outputSet[hex.EncodeToString(output[:])] = struct{}{}
		}
	}

	outputs := make([]string, 0, len(outputSet))
	for item := range outputSet {
		outputs = append(outputs, item)
	}
	sort.Strings(outputs)
	return outputs, nil
}

func buildReceiverBundle(network string, keys *ReceiverKeysRequest, labels []uint32) (*receiverBundle, error) {
	mainnet, err := mainnetFlag(network)
	if err != nil {
		return nil, err
	}
	scanBytes, err := decodeFixedHex(keys.ScanPrivkey, 32, "invalid receiver scan_privkey")
	if err != nil {
		return nil, err
	}
	spendBytes, err := decodeFixedHex(keys.SpendPrivkey, 32, "invalid receiver spend_privkey")
	if err != nil {
		return nil, err
	}

	var scanPrivkey [32]byte
	var spendPrivkey [32]byte
	copy(scanPrivkey[:], scanBytes)
	copy(spendPrivkey[:], spendBytes)
	_, scanPubkeyRaw := btcec.PrivKeyFromBytes(scanPrivkey[:])
	_, spendPubkeyRaw := btcec.PrivKeyFromBytes(spendPrivkey[:])
	var scanPubkey [33]byte
	var spendPubkey [33]byte
	copy(scanPubkey[:], scanPubkeyRaw.SerializeCompressed())
	copy(spendPubkey[:], spendPubkeyRaw.SerializeCompressed())

	address, err := bip352.CreateAddress(scanPubkey, spendPubkey, mainnet, 0)
	if err != nil {
		return nil, err
	}
	addresses := []string{address}
	for _, label := range labels {
		labeledAddress, err := bip352.CreateLabeledAddress(
			scanPubkey,
			spendPubkey,
			mainnet,
			0,
			scanPrivkey,
			label,
		)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, labeledAddress)
	}

	return &receiverBundle{
		addresses:    addresses,
		scanPrivkey:  scanPrivkey,
		scanPubkey:   scanPubkey,
		spendPrivkey: spendPrivkey,
		spendPubkey:  spendPubkey,
	}, nil
}

func buildLabels(scanPrivkey [32]byte, labelValues []uint32) ([]*bip352.Label, error) {
	labels := make([]*bip352.Label, 0, len(labelValues))
	for _, value := range labelValues {
		label, err := bip352.CreateLabel(scanPrivkey, value)
		if err != nil {
			return nil, err
		}
		labelCopy := label
		labels = append(labels, &labelCopy)
	}
	return labels, nil
}

func decodeOutputsToScan(values []string) ([][32]byte, error) {
	outputs := make([][32]byte, 0, len(values))
	for _, value := range values {
		outputBytes, err := decodeFixedHex(value, 32, "malformed public key")
		if err != nil {
			return nil, err
		}
		var output [32]byte
		copy(output[:], outputBytes)
		outputs = append(outputs, output)
	}
	return outputs, nil
}

func sumPublicKeys(pubKeys [][33]byte) ([33]byte, error) {
	accX := new(big.Int)
	accY := new(big.Int)
	for _, serialized := range pubKeys {
		pubKey, err := btcec.ParsePubKey(serialized[:])
		if err != nil {
			return [33]byte{}, err
		}
		accX, accY = btcec.S256().Add(accX, accY, pubKey.X(), pubKey.Y())
	}
	if accX.Sign() == 0 && accY.Sign() == 0 {
		return [33]byte{}, errPointAtInfinity
	}

	var xField btcec.FieldVal
	var yField btcec.FieldVal
	if overflow := xField.SetByteSlice(accX.Bytes()); overflow {
		return [33]byte{}, errors.New("invalid summed public key")
	}
	if overflow := yField.SetByteSlice(accY.Bytes()); overflow {
		return [33]byte{}, errors.New("invalid summed public key")
	}

	return bip352.ConvertToFixedLength33(btcec.NewPublicKey(&xField, &yField).SerializeCompressed()), nil
}

func deriveTweak(aSum [33]byte, inputHash [32]byte) ([33]byte, error) {
	return bip352.TweakPubkey(aSum, inputHash)
}

func deriveReceiveSharedSecret(aSum [33]byte, scanPrivkey [32]byte, inputHash [32]byte) ([33]byte, error) {
	inputHashCopy := inputHash
	return bip352.CreateSharedSecret(aSum, scanPrivkey, &inputHashCopy)
}

func scanOutputs(
	receiverSpendPubkey [33]byte,
	labels []*bip352.Label,
	outputsToScan [][32]byte,
	sharedSecret [33]byte,
	detailedOutputsRequired bool,
) (int, []FoundOutput, []string, error) {
	remaining := make([][32]byte, len(outputsToScan))
	copy(remaining, outputsToScan)
	foundOutputs := make([]FoundOutput, 0)
	foundCount := 0

	for k := uint32(0); k < kMax; {
		outputPubkey, tweak, err := bip352.CreateOutputPubKeyTweak(sharedSecret, receiverSpendPubkey, k)
		if err != nil {
			return 0, nil, nil, err
		}

		found := false
		for i, txOutput := range remaining {
			if bytes.Equal(outputPubkey[:], txOutput[:]) {
				foundCount++
				if detailedOutputsRequired {
					foundOutputs = append(foundOutputs, FoundOutput{
						PubKey:       hex.EncodeToString(txOutput[:]),
						PrivKeyTweak: hex.EncodeToString(tweak[:]),
					})
				}
				remaining = append(remaining[:i], remaining[i+1:]...)
				found = true
				k++
				break
			}

			if labels == nil {
				continue
			}

			matchedOutput, label, err := matchOutputLabel(txOutput, outputPubkey, labels)
			if err != nil {
				return 0, nil, nil, err
			}
			if label == nil {
				continue
			}

			foundCount++
			if detailedOutputsRequired {
				fullTweak := bip352.AddPrivateKeys(tweak, label.Tweak)
				foundOutputs = append(foundOutputs, FoundOutput{
					PubKey:       hex.EncodeToString(matchedOutput[:]),
					PrivKeyTweak: hex.EncodeToString(fullTweak[:]),
				})
			}
			remaining = append(remaining[:i], remaining[i+1:]...)
			found = true
			k++
			break
		}

		if !found {
			break
		}
	}

	notes := []string{}
	if len(outputsToScan) > kMax && foundCount == kMax {
		notes = append(notes, "scan_limit_reached")
	}
	if !detailedOutputsRequired {
		notes = append(notes, "count_only_expectation")
		return foundCount, []FoundOutput{}, notes, nil
	}

	sort.Slice(foundOutputs, func(i, j int) bool {
		if foundOutputs[i].PubKey != foundOutputs[j].PubKey {
			return foundOutputs[i].PubKey < foundOutputs[j].PubKey
		}
		return foundOutputs[i].PrivKeyTweak < foundOutputs[j].PrivKeyTweak
	})
	return foundCount, foundOutputs, notes, nil
}

func matchOutputLabel(
	txOutput [32]byte,
	outputPubkey [32]byte,
	labels []*bip352.Label,
) ([32]byte, *bip352.Label, error) {
	prependedTxOutput := bip352.ConvertToFixedLength33(append([]byte{0x02}, txOutput[:]...))
	prependedOutputPubkey := bip352.ConvertToFixedLength33(append([]byte{0x02}, outputPubkey[:]...))

	label, err := bip352.MatchLabels(prependedTxOutput, prependedOutputPubkey, labels)
	if err != nil {
		return [32]byte{}, nil, err
	}
	if label != nil {
		return txOutput, label, nil
	}

	txOutputNegatedCompressed, err := bip352.NegatePublicKey(prependedTxOutput)
	if err != nil {
		return [32]byte{}, nil, err
	}
	label, err = bip352.MatchLabels(txOutputNegatedCompressed, prependedOutputPubkey, labels)
	if err != nil {
		return [32]byte{}, nil, err
	}
	if label != nil {
		return bip352.ConvertToFixedLength32(txOutputNegatedCompressed[1:]), label, nil
	}
	return [32]byte{}, nil, nil
}

func sumInputSecretKeys(inputs []eligibleSendInput) ([32]byte, error) {
	if len(inputs) == 0 {
		return [32]byte{}, errNoEligibleInputs
	}

	terms := make([][32]byte, 0, len(inputs))
	for _, input := range inputs {
		secretKey := input.secretKey
		if input.isTaproot && secretKeyHasOddY(secretKey) {
			secretKey = bip352.NegateSecretKey(secretKey)
		}
		terms = append(terms, secretKey)
	}

	sum := bip352.RecursiveAddPrivateKeys(terms)
	if isZero32(sum) {
		return sum, errZeroScalar
	}
	return sum, nil
}

func scanGroupRecipientLimitExceeded(groups []scanGroup) bool {
	counts := make(map[string]int)
	for _, group := range groups {
		if group.limitExceeded {
			return true
		}
		counts[group.scanPubkeyHex] += len(group.spendPubkeys)
		if counts[group.scanPubkeyHex] > kMax {
			return true
		}
	}
	return false
}

func secretKeyHasOddY(secretKey [32]byte) bool {
	_, pubkey := btcec.PrivKeyFromBytes(secretKey[:])
	return pubkey.Y().Bit(0) == 1
}

func isZero32(value [32]byte) bool {
	return value == [32]byte{}
}

func decodeWitnessStack(values []string) ([][]byte, error) {
	stack := make([][]byte, 0, len(values))
	for _, value := range values {
		bytesValue, err := hex.DecodeString(value)
		if err != nil {
			return nil, err
		}
		stack = append(stack, bytesValue)
	}
	return stack, nil
}

func decodeOptionalHex(value *string) ([]byte, error) {
	if value == nil {
		return []byte{}, nil
	}
	return hex.DecodeString(*value)
}

func decodeRequiredHex(value *string, message string) ([]byte, error) {
	if value == nil {
		return nil, errors.New(message)
	}
	return hex.DecodeString(*value)
}

func decodeFixedHex(value string, expectedLen int, message string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) != expectedLen {
		return nil, errors.New(message)
	}
	return decoded, nil
}

func mainnetFlag(network string) (bool, error) {
	switch network {
	case "mainnet":
		return true, nil
	case "testnet", "regtest":
		return false, nil
	default:
		return false, fmt.Errorf("unsupported network: %s", network)
	}
}

func isP2TR(scriptPubkey []byte) bool {
	return len(scriptPubkey) == 34 && scriptPubkey[0] == 0x51 && scriptPubkey[1] == 0x20
}

func isP2WPKH(scriptPubkey []byte) bool {
	return len(scriptPubkey) == 22 && scriptPubkey[0] == 0x00 && scriptPubkey[1] == 0x14
}

func isP2PKH(scriptPubkey []byte) bool {
	return len(scriptPubkey) == 25 &&
		scriptPubkey[0] == 0x76 &&
		scriptPubkey[1] == 0xA9 &&
		scriptPubkey[2] == 0x14 &&
		scriptPubkey[23] == 0x88 &&
		scriptPubkey[24] == 0xAC
}

func isP2SH(scriptPubkey []byte) bool {
	return len(scriptPubkey) == 23 &&
		scriptPubkey[0] == 0xA9 &&
		scriptPubkey[1] == 0x14 &&
		scriptPubkey[22] == 0x87
}
