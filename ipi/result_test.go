package ipi

import "testing"

func TestComputeThreat(t *testing.T) {
	tests := []struct {
		name      string
		isTor     bool
		isVPN     bool
		isProxy   bool
		isHosting bool
		wantScore int
		wantLevel ThreatLevel
	}{
		{
			name:      "no flags",
			wantScore: 0, wantLevel: ThreatNone,
		},
		{
			name:      "hosting only",
			isHosting: true,
			wantScore: 1, wantLevel: ThreatLow,
		},
		{
			name:      "vpn only",
			isVPN:     true,
			wantScore: 2, wantLevel: ThreatMedium,
		},
		{
			name:      "proxy only",
			isProxy:   true,
			wantScore: 2, wantLevel: ThreatMedium,
		},
		{
			name:      "tor only",
			isTor:     true,
			wantScore: 3, wantLevel: ThreatMedium,
		},
		{
			name:      "vpn + hosting",
			isVPN:     true,
			isHosting: true,
			wantScore: 3, wantLevel: ThreatMedium,
		},
		{
			name:      "tor + hosting",
			isTor:     true,
			isHosting: true,
			wantScore: 4, wantLevel: ThreatHigh,
		},
		{
			name:      "vpn + proxy",
			isVPN:     true,
			isProxy:   true,
			wantScore: 4, wantLevel: ThreatHigh,
		},
		{
			name:      "tor + vpn",
			isTor:     true,
			isVPN:     true,
			wantScore: 5, wantLevel: ThreatHigh,
		},
		{
			name:      "tor + proxy + hosting",
			isTor:     true,
			isProxy:   true,
			isHosting: true,
			wantScore: 6, wantLevel: ThreatCritical,
		},
		{
			name:      "all flags",
			isTor:     true,
			isVPN:     true,
			isProxy:   true,
			isHosting: true,
			wantScore: 8, wantLevel: ThreatCritical,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &Result{
				IsTor:     tc.isTor,
				IsVPN:     tc.isVPN,
				IsProxy:   tc.isProxy,
				IsHosting: tc.isHosting,
			}
			computeThreat(r)
			if r.Score != tc.wantScore {
				t.Errorf("Score = %d, want %d", r.Score, tc.wantScore)
			}
			if r.Threat != tc.wantLevel {
				t.Errorf("Threat = %s, want %s", r.Threat, tc.wantLevel)
			}
		})
	}
}

func TestThreatLevelString(t *testing.T) {
	tests := []struct {
		level ThreatLevel
		want  string
	}{
		{ThreatNone, "None"},
		{ThreatLow, "Low"},
		{ThreatMedium, "Medium"},
		{ThreatHigh, "High"},
		{ThreatCritical, "Critical"},
		{ThreatLevel(99), "ThreatLevel(99)"},
	}
	for _, tc := range tests {
		if got := tc.level.String(); got != tc.want {
			t.Errorf("ThreatLevel(%d).String() = %q, want %q", int(tc.level), got, tc.want)
		}
	}
}
