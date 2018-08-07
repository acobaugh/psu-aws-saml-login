package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStringInSlice(t *testing.T) {
	needle := "needle"
	haystackA := []string{"foo", "bar", "baz", "needle"}
	haystackB := []string{"foo", "bar", "baz"}

	assert.True(t, stringInSlice(needle, haystackA), "is true")

	assert.False(t, stringInSlice(needle, haystackB), "is false")
}
