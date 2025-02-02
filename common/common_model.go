package common

type Page[T any] struct {
	Elements      []T   `json:"elements"`
	TotalElements int64 `json:"totalElements"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type InfoResponse struct {
	Env       string `json:"env"`
	Hostname  string `json:"hostname"`
	IP        string `json:"ip"`
	UserAgent string `json:"userAgent"`
}
