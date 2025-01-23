package api

import "time"

type (
	Thread struct {
		ID        string    `json:"id"`
		Title     string    `json:"title"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
		Saved     bool      `json:"saved"`
		Pinned    bool      `json:"pinned"`
		Shared    bool      `json:"shared"`
		BranchID  string    `json:"branch_id"`
		Profile   *Profile  `json:"profile,omitempty"`
	}

	ThreadInfo struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
		SessionId string    `json:"session_id"`
	}

	Profile struct {
		ID                *string `json:"id"`
		Name              *string `json:"name"`
		Model             string  `json:"model"`
		ModelName         string  `json:"model_name"`
		ModelProvider     string  `json:"model_provider"`
		ModelProviderName string  `json:"model_provider_name"`
		ModelInputLimit   int     `json:"model_input_limit"`
		InternetAccess    bool    `json:"internet_access"`
		Personalizations  bool    `json:"personalizations"`
		Lens              *Lens   `json:"lens,omitempty"`
		Shortcut          *string `json:"shortcut"`
	}

	Lens struct {
		ID   int     `json:"id"`
		Name *string `json:"name"`
	}
)
