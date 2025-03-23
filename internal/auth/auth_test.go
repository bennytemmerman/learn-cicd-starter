package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid API Key",
			headers:     http.Header{"Authorization": []string{"ApiKey valid-key"}},
			expectedKey: "valid-key",
			expectError: false,
			errorMsg:    "",
		},
		{
			name:        "Missing Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectError: true,
			errorMsg:    "no authorization header included",
		},
		{
			name:        "Malformed Authorization Header - Missing ApiKey Prefix",
			headers:     http.Header{"Authorization": []string{"Bearer invalid-key"}},
			expectedKey: "",
			expectError: true,
			errorMsg:    "malformed authorization header",
		},
		{
			name:        "Malformed Authorization Header - Incorrect Format",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectError: true,
			errorMsg:    "malformed authorization header",
		},
		{
			name:        "Empty API Key",
			headers:     http.Header{"Authorization": []string{"ApiKey "}},
			expectedKey: "",
			expectError: true,
			errorMsg:    "malformed authorization header",
		},
		{
			name:        "Multiple Spaces in Authorization Header",
			headers:     http.Header{"Authorization": []string{"ApiKey    valid-key"}},
			expectedKey: "valid-key",
			expectError: false,
			errorMsg:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check if an error was expected
			if tt.expectError {
				if err == nil {
					t.Errorf("expected an error but got none")
				} else if err.Error() != tt.errorMsg {
					t.Errorf("expected error message '%s' but got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}

			// Check if the returned key matches the expected key
			if key != tt.expectedKey {
				t.Errorf("expected key '%s' but got '%s'", tt.expectedKey, key)
			}
		})
	}
}
