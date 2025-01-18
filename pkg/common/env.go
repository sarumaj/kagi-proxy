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
