// SPDX-License-Identifier: MIT
#ifndef SP_DIFFER_SEMANTIC_H
#define SP_DIFFER_SEMANTIC_H

/*
 * SP-DIFFER Semantic Worker Interface (v1)
 *
 * This header defines the stable C ABI used by semantic workers.
 * Semantic workers accept a UTF-8 JSON request payload following
 * spec/SEMANTIC_ADAPTER.md and return a UTF-8 JSON response payload
 * following spec/SEMANTIC_CONTRACT.md.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SP_DIFFER_SEMANTIC_WORKER_API_VERSION 1

/*
 * Returns the semantic worker ABI version.
 * Must return SP_DIFFER_SEMANTIC_WORKER_API_VERSION.
 */
uint32_t sp_differ_semantic_worker_api_version(void);

/*
 * Executes a single semantic request.
 *
 * Inputs:
 *   - input: pointer to UTF-8 JSON request bytes
 *   - input_len: number of request bytes
 *
 * Outputs:
 *   - output: pointer to a worker-owned UTF-8 JSON response buffer
 *   - output_len: number of response bytes
 *
 * Ownership:
 *   - The worker owns the output buffer and must free it via
 *     sp_differ_semantic_worker_free.
 *
 * Returns:
 *   - 0 on success
 *   - nonzero on failure (no output is produced)
 */
int sp_differ_semantic_worker_run(const uint8_t* input, size_t input_len,
                                  uint8_t** output, size_t* output_len);

/*
 * Frees a buffer returned by sp_differ_semantic_worker_run.
 */
void sp_differ_semantic_worker_free(uint8_t* output);

#ifdef __cplusplus
}
#endif

#endif /* SP_DIFFER_SEMANTIC_H */
