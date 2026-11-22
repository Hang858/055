# light-lattice vendor sources

Downloaded from <https://light-lattice.org/> on 2026-11-22.

| Package | Version | Source |
|---|---|---|
| BiT | v2.1 (2026-11-06) | `https://light-lattice.org/bit/implementations/20261106/BiT-20261106.zip` |
| PolarLAC | v1.0 (2026-09-20) | `https://light-lattice.org/polarlac/implementations/20260920/PolarLAC.zip` |

Included:

- `bit/common/` and `bit/ref/BiT-{128,256,512}/` — BiT reference C sources and headers;
- `polarlac/POLARLAC-{128,256,512,Light,512-Star}/` — PolarLAC reference x86
  implementation sources and headers.

The vendor files are unmodified.  `build.sh` compiles each security level into a
separate shared library under `lib/`:

```sh
./build.sh
# LIGHTLATTICE_LIBDIR=$PWD/lib
```

Separate `.so` files are intentional: BiT/PolarLAC have global DRNG state and
reuse generic symbol names (`kem_keygen`, `sig_keygen`, `drng_algorithm`).
Loading them independently avoids symbol collisions and lets an updated
algorithm replace one `.so` without rebuilding TLS.

The adapter `../lightlattice.c` dlopens these libraries and exposes them through
`pq_alg` descriptors.  Machine-readable build results and TLS matrix notes are in
`docs/light-lattice集成-20261122.md`.

License/copyright remains with the original authors (ICCS / Institute of
Information Engineering, CAS); see the headers in each vendor file and the
`Intellectual property` document in the PolarLAC package.
