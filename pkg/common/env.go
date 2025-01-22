package common

import (
	"os"
	"reflect"
	"strconv"
)

// Getenv returns the value of the environment variable with the given key.
func Getenv[T any](key string, fallback T) (out T) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback
	}

	target := reflect.ValueOf(&out).Elem()

	switch target.Kind() {
	case reflect.Bool:
		v, _ := strconv.ParseBool(raw)
		target.Set(reflect.ValueOf(v))
		return target.Interface().(T)

	case reflect.Float32, reflect.Float64:
		v, _ := strconv.ParseFloat(raw, 64)
		target.Set(reflect.ValueOf(v).Convert(target.Type()))
		return target.Interface().(T)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, _ := strconv.ParseInt(raw, 10, 64)
		target.Set(reflect.ValueOf(v).Convert(target.Type()))
		return target.Interface().(T)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v, _ := strconv.ParseUint(raw, 10, 64)
		target.Set(reflect.ValueOf(v).Convert(target.Type()))
		return target.Interface().(T)

	case reflect.String:
		return any(raw).(T)

	default:
		return fallback

	}
}

// QuickGet is a type assertion helper for getting values from a map or an interface.
// It supports the following types:
// - map[string]T
// - map[string]any
// - interface{ Get(string) T }
// - interface{ Get(string) any }
// - interface{ Get(string) (T, bool) }
// - interface{ Get(string) (any, bool) }
// - interface{ Get(any) T }
// - interface{ Get(any) any }
// - interface{ Get(any) (T, bool) }
// - interface{ Get(any) (any, bool) }
func QuickGet[T, M any](m M, key string) (val T) {
	switch m := any(m).(type) {
	case map[string]T:
		return m[key]

	case map[string]any:
		v, _ := m[key].(T)
		return v

	case map[any]T:
		return m[key]

	case map[any]any:
		v, _ := m[key].(T)
		return v

	case interface{ Get(string) T }:
		return m.Get(key)

	case interface{ Get(string) (T, bool) }:
		v, _ := m.Get(key)
		return v

	case interface{ Get(string) any }:
		v, _ := m.Get(key).(T)
		return v

	case interface{ Get(string) (any, bool) }:
		v, _ := m.Get(key)
		v2, _ := v.(T)
		return v2

	case interface{ Get(any) T }:
		return m.Get(key)

	case interface{ Get(any) (T, bool) }:
		v, _ := m.Get(key)
		return v

	case interface{ Get(any) any }:
		v, _ := m.Get(key).(T)
		return v

	case interface{ Get(any) (any, bool) }:
		v, _ := m.Get(key)
		v2, _ := v.(T)
		return v2

	}

	return
}
