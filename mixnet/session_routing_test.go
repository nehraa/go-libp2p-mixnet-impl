package mixnet

import "testing"

func TestSessionRoutingEnabledOnlyForHeaderOnly(t *testing.T) {
	tests := []struct {
		name string
		cfg  *MixnetConfig
		want bool
	}{
		{name: "nil config", cfg: nil, want: false},
		{name: "disabled", cfg: &MixnetConfig{EnableSessionRouting: false, EncryptionMode: EncryptionModeHeaderOnly}, want: false},
		{name: "header only enabled", cfg: &MixnetConfig{EnableSessionRouting: true, EncryptionMode: EncryptionModeHeaderOnly}, want: true},
		{name: "full onion enabled", cfg: &MixnetConfig{EnableSessionRouting: true, EncryptionMode: EncryptionModeFull}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionRoutingEnabled(tc.cfg); got != tc.want {
				t.Fatalf("sessionRoutingEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}
