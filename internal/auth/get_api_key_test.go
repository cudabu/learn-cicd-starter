package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers http.Header
		want    string
		wantErr error
	}{
		"no auth header": {
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"malformed header, no ApiKey prefix": {
			headers: http.Header{"Authorization": []string{"Bearer abc123"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		"malformed header, missing key": {
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		"valid header": {
			headers: http.Header{"Authorization": []string{"ApiKey abc123"}},
			want:    "abc123",
			wantErr: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if got != tt.want {
				t.Errorf("got key %q, want %q", got, tt.want)
			}

			if (err == nil) != (tt.wantErr == nil) {
				t.Fatalf("got err %v, want err %v", err, tt.wantErr)
			}
			if err != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("got err %q, want %q", err.Error(), tt.wantErr.Error())
			}
		})
	}
}
