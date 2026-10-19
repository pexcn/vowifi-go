package runtimehost

import (
	"encoding/json"
	"testing"

	"github.com/iniwex5/vowifi-go/internal/ims"
	"github.com/iniwex5/vowifi-go/runtimehost/messaging"
)

func TestUSSDJSONPreservesFrontendMenuContract(t *testing.T) {
	for _, done := range []bool{false, true} {
		b, err := json.Marshal(publicUSSD(ims.USSDResult{SessionID: "dialog", Text: "余额", Done: done}))
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err = json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		wantStatus := float64(1)
		if done {
			wantStatus = 0
		}
		if got["status"] != wantStatus || got["session_id"] != "dialog" || got["text"] != "余额" || got["done"] != done {
			t.Fatalf("frontend cannot continue menu: %s", b)
		}
	}
}
func TestDeliveryJSONPreservesPollingContract(t *testing.T) {
	b, err := json.Marshal(messaging.DeliveryStatus{MessageID: "message", ICCID: "sim", PartsTotal: 2, Parts: []messaging.DeliveryPartStatus{{PartNo: 1, RPMR: 42, SIPCode: 202}}})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err = json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["message_id"] != "message" || got["iccid"] != "sim" || got["parts_total"] != float64(2) {
		t.Fatalf("delivery keys: %s", b)
	}
	part := got["parts"].([]any)[0].(map[string]any)
	if part["part_no"] != float64(1) || part["rp_mr"] != float64(42) || part["sip_code"] != float64(202) {
		t.Fatalf("part keys: %s", b)
	}
}
