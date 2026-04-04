package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"spdiffer/adapters/go_bip352/semantic"
)

//export sp_differ_semantic_worker_api_version
func sp_differ_semantic_worker_api_version() C.uint32_t {
	return C.uint32_t(semantic.SemanticWorkerAPIVersion)
}

//export sp_differ_semantic_worker_run
func sp_differ_semantic_worker_run(
	input *C.uint8_t,
	inputLen C.size_t,
	output **C.uint8_t,
	outputLen *C.size_t,
) C.int {
	if output == nil || outputLen == nil {
		return 1
	}

	*output = nil
	*outputLen = 0

	if input == nil && inputLen != 0 {
		return 1
	}

	var request string
	if inputLen != 0 {
		request = string(C.GoBytes(unsafe.Pointer(input), C.int(inputLen)))
	}

	response, err := semantic.RunRequestJSON(request)
	if err != nil {
		return 1
	}

	responseBytes := []byte(response)
	if len(responseBytes) == 0 {
		allocation := C.malloc(1)
		if allocation == nil {
			return 1
		}
		*output = (*C.uint8_t)(allocation)
		*outputLen = 0
		return 0
	}

	allocation := C.CBytes(responseBytes)
	if allocation == nil {
		return 1
	}
	*output = (*C.uint8_t)(allocation)
	*outputLen = C.size_t(len(responseBytes))
	return 0
}

//export sp_differ_semantic_worker_free
func sp_differ_semantic_worker_free(output *C.uint8_t) {
	if output != nil {
		C.free(unsafe.Pointer(output))
	}
}

func main() {}
