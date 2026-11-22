#!/usr/bin/env bash
# Build the light-lattice algorithms as isolated shared libraries.
# Each level is a separate .so so vendor symbols can never collide, and the
# TLS adapter can load/replace them independently.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "$0")" && pwd)
OUT=$ROOT/lib
CC=${CC:-cc}
CFLAGS=${CFLAGS:--O2 -fPIC -shared -std=c99 -Wall -Wextra}
mkdir -p "$OUT"

bit_common=(
  "$ROOT/bit/common/sample.c"
  "$ROOT/bit/common/sign.c"
  "$ROOT/bit/common/spectral.c"
  "$ROOT/bit/common/symmetric.c"
  "$ROOT/bit/common/signature_api.c"
)
for level in 128 256 512; do
  d=$ROOT/bit/ref/BiT-$level
  srcs=("${bit_common[@]}")
  if [[ $level != 512 ]]; then
    srcs+=("$ROOT/bit/common/signature_codec_$level.c" "$ROOT/bit/common/polyvec_ref.c")
  else
    srcs+=("$d/polyvec.c")
  fi
  srcs+=("$d/drng.c" "$d/fips202.c" "$d/ntt.c" "$d/packing.c" "$d/parabola.c" "$d/poly.c")
  "$CC" $CFLAGS -DBIT_IMPL_AVX=0 -I"$d" -I"$ROOT/bit/common" \
    "${srcs[@]}" "$ROOT/drng_global.c" -lm -o "$OUT/libbit-$level.so"
  echo "built $OUT/libbit-$level.so"
done

for level in POLARLAC-128 POLARLAC-256 POLARLAC-512 POLARLAC-Light POLARLAC-512-Star; do
  d=$ROOT/polarlac/$level
  "$CC" $CFLAGS -DBIT_USE_SHAKE=0 -I"$d" \
    "$d/auxfunc.c" "$d/drng.c" "$d/fips202.c" "$d/symmetric.c" \
    "$d/sample.c" "$d/poly.c" "$d/pke.c" "$d/polar.c" "$d/ntt.c" "$d/fft.c" \
    "$d/KEM_AlgorithmInstance.c" "$ROOT/drng_global.c" -lm \
    -o "$OUT/libpolarlac-${level#POLARLAC-}.so"
  echo "built $OUT/libpolarlac-${level#POLARLAC-}.so"
done
