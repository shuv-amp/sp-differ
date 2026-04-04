package main

import (
	"fmt"
	"io"
	"os"

	"spdiffer/adapters/go_bip352/semantic"
)

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	response, err := semantic.RunRequestJSON(string(input))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	fmt.Println(response)
}
