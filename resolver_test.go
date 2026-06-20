package main

import (
	"fmt"
	"testing"
)

func TestEncodeDNSName(t *testing.T) {
	data, err := encodeDNSName("google.com")
	if err != nil {
		t.Errorf("got err: %v", err)
	}
	fmt.Printf("response: %v\n", data)
}

func TestBuildQuery(t *testing.T) {
	data, err := buildQuery("google.com", 1)
	if err != nil {
		t.Errorf("got err: %v", err)
	}
	fmt.Printf("response: %v\n", data)
}

func TestBuildQueryGolden(t *testing.T) {
	data, err := buildQuery("www.example.com", 1)
	if err != nil {
		t.Errorf("got err: %v", err)
	}
	expected := "00010100000100000000000003777777076578616d706c6503636f6d0000010001"
	result := fmt.Sprintf("%x", data)
	if expected != result {
		t.Errorf("result: %v, expected: %v", result, expected)
	}
}
