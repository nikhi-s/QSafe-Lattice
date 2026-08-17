
"""Run configuration -- single source of truth for the RSA benchmark,
pre-flight checks, and post-run verification. Change values here ONLY."""
 
KEY_SIZES = [1024, 2048, 3072, 4096, 8192]
MESSAGE_SIZES = [16, 32, 64, 128, 256, 512, 1024]
KEY_SIZE_SAMPLES = {1024: 500, 2048: 100, 3072: 100, 4096: 100, 8192: 100}
