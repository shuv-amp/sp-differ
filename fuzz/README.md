# Fuzzing

This folder stores semantic-worker fuzz harnesses, seed corpora, and mutation dictionaries.

Current contents:
- `corpus/semantic_worker/` contains deterministic valid and invalid seeds for the semantic worker ABI.
- `dictionaries/semantic_request.dict` contains JSON tokens used by the raw-byte mutator.
- `scripts/generate_semantic_fuzz_corpus.py` regenerates and checks the corpus.
- `scripts/run_semantic_worker_fuzz.py` runs structured and raw-byte fuzzing against a semantic worker shared library with replayable artifacts.
- `scripts/semantic_fuzz_minimizer.py` shrinks failures while preserving the same failure signature.
- Structured fuzz mutations now generate valid secp256k1 pubkeys and secret scalars for the key fields they randomize, which keeps the deterministic lane focused on semantic behavior.
- `.github/workflows/ci.yml` runs short deterministic fuzz jobs on normal CI, and `.github/workflows/nightly-fuzz.yml` runs longer scheduled fuzz jobs with tarred artifact upload.

Useful commands:

```bash
make fuzz-corpus
make fuzz-minimizer-smoke
make fuzz-semantic-spdk
make fuzz-semantic-silent-payments
make fuzz-semantic-bip352
make fuzz-semantic-go-bip352
make fuzz-semantic-workers FUZZ_STRUCTURED_ITERATIONS=64 FUZZ_RAW_ITERATIONS=64
```
