package semantic

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixturePath(name string) string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "tests", "fixtures", name)
}

func runFixtureValue(t *testing.T, name string) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	response, err := RunRequestJSON(string(payload))
	if err != nil {
		t.Fatalf("run request: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(response), &value); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return value
}

func runFixtureError(t *testing.T, name string) string {
	t.Helper()
	payload, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	_, err = RunRequestJSON(string(payload))
	if err == nil {
		t.Fatalf("expected request to fail")
	}
	return err.Error()
}

func TestSendInputHashUsesPrivkeySumNotRevealedInputPubkeys(t *testing.T) {
	actual := runFixtureValue(t, "send_input_hash_uses_privkey_sum.request.json")
	if actual["input_hash"] != "2c1a59f99aa869070068150bb4a394c4bed7aebba055b5408b7c503b2649932c" {
		t.Fatalf("unexpected input_hash: %v", actual["input_hash"])
	}
	sharedSecrets, ok := actual["sender_shared_secrets"].([]any)
	if !ok || len(sharedSecrets) != 1 {
		t.Fatalf("unexpected sender_shared_secrets: %#v", actual["sender_shared_secrets"])
	}
	secretEntry, ok := sharedSecrets[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected sender_shared_secrets entry: %#v", sharedSecrets[0])
	}
	if secretEntry["shared_secret"] != "02c8f4ce9acc0685424176e150b74244699304f994be15f4d41f49a6c1319826fe" {
		t.Fatalf("unexpected sender shared secret: %v", secretEntry["shared_secret"])
	}
}

func TestReceivePointAtInfinityShortCircuitsBeforeScanningOutputs(t *testing.T) {
	actual := runFixtureValue(t, "receive_point_at_infinity_ignores_malformed_outputs.request.json")
	if actual["semantic_status"] != "point_at_infinity" {
		t.Fatalf("unexpected semantic_status: %v", actual["semantic_status"])
	}
	if actual["input_hash"] != nil {
		t.Fatalf("expected nil input_hash, got %v", actual["input_hash"])
	}
	if actual["shared_secret"] != nil {
		t.Fatalf("expected nil shared_secret, got %v", actual["shared_secret"])
	}
}

func TestReceiveRejectsMalformedOutputPubkeys(t *testing.T) {
	err := runFixtureError(t, "receive_rejects_malformed_output_pubkeys.request.json")
	if !strings.Contains(err, "invalid public key:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReceiveRejectsMalformedOutputBeforePointAtInfinity(t *testing.T) {
	err := runFixtureError(t, "receive_rejects_malformed_output_before_point_at_infinity.request.json")
	if !strings.Contains(err, "invalid public key:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReceiveRejectsMissingWitnessPubkey(t *testing.T) {
	err := runFixtureError(t, "receive_rejects_missing_witness_pubkey.request.json")
	if err != "failed to parse input pubkey: missing witness pubkey" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendRejectsRecipientGroupsBeyondKMax(t *testing.T) {
	payload, err := os.ReadFile(fixturePath("send_input_hash_uses_privkey_sum.request.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	request["recipient_groups"] = []map[string]any{
		{
			"count":        float64(kMax + 1),
			"scan_pubkey":  "02062d49ffc02787d586c608dfbec184aa91a6597d97b463ea5c6babd9d17a95a3",
			"spend_pubkey": "0381eb9a9a9ec739d527c1631b31b421566f5c2a47b4ab5b1f6a686dfb68eab716",
		},
	}
	payload, err = json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	response, err := RunRequestJSON(string(payload))
	if err != nil {
		t.Fatalf("run request: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(response), &value); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if value["semantic_status"] != "recipient_limit_exceeded" {
		t.Fatalf("unexpected semantic_status: %v", value["semantic_status"])
	}
	notes, ok := value["notes"].([]any)
	if !ok || len(notes) != 1 || notes[0] != "per_group_recipient_limit_exceeded" {
		t.Fatalf("unexpected notes: %#v", value["notes"])
	}
}
