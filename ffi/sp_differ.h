#ifndef SP_DIFFER_H
#define SP_DIFFER_H

/*
 * SP-DIFFER Worker Interface (v1)
 *
 * This header defines the stable C ABI used by worker implementations.
 * Workers accept a canonical case payload (see spec/FORMAT.md) and return
 * a serialized result payload using the same versioned schema.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SP_DIFFER_WORKER_API_VERSION 1

typedef enum sp_differ_status {
  SP_DIFFER_STATUS_OK = 0,
  SP_DIFFER_STATUS_INVALID_INPUT = 1,
  SP_DIFFER_STATUS_POINT_AT_INFINITY = 2,
  SP_DIFFER_STATUS_ZERO_SCALAR = 3,
  SP_DIFFER_STATUS_INVALID_PUBKEY = 4,
  SP_DIFFER_STATUS_TWEAK_OUT_OF_RANGE = 5,
  SP_DIFFER_STATUS_INTERNAL = 255,
} sp_differ_status;

/*
 * Returns the worker ABI version. Must return SP_DIFFER_WORKER_API_VERSION.
 */
uint32_t sp_differ_worker_api_version(void);

/*
 * Executes a single test case.
 *
 * Inputs:
 *   - input: pointer to canonical case bytes (spec/FORMAT.md)
 *   - input_len: length of input in bytes
 *
 * Outputs:
 *   - output: pointer to a worker-owned buffer with serialized result bytes
 *   - output_len: length of the output buffer in bytes
 *
 * Ownership:
 *   - The worker owns the output buffer and must free it via
 *     sp_differ_worker_free.
 *
 * Returns:
 *   - 0 on success, nonzero on failure (no output is produced).
 */
int sp_differ_worker_run(const uint8_t* input, size_t input_len,
                         uint8_t** output, size_t* output_len);

/*
 * Frees a buffer returned by sp_differ_worker_run.
 */
void sp_differ_worker_free(uint8_t* output);

#ifdef __cplusplus
}
#endif

#endif /* SP_DIFFER_H */
