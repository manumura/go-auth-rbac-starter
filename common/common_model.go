package common

type Page[T any] struct {
	Elements      []T   `json:"elements"`
	TotalElements int64 `json:"totalElements"`
}
