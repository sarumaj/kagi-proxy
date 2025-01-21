package common

// QuickGet is a type assertion helper for map values.
func QuickGet[T any](m map[string]any, key string) T {
	v, _ := m[key].(T)
	return v
}
