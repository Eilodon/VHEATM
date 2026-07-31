# v16.1.1 → V17 migration map

## Preserved concepts

- Core Loop + Specialist Lenses + Meta-Defense.
- FAST / Standard / Full execution modes.
- MVP / Production / Critical target tiers.
- Evidence anchors, pattern globalization, fix verification, adversarial pass, independent judge, execution fidelity, and lifecycle learning.

## Canonical corrections

- Hard gates: **22 = 9 core + 8 triggered + 5 meta**.
- Phases: **8 = P, V, G, E, A, T, M, KB**.
- Version authority: `manifests/vheatm-v17.yaml` only.
- Output contracts: JSON Schema 2020-12, not illustrative YAML containing placeholders or emoji-prefixed keys.
- Defaults: security-relevant declarations begin at `unknown`, not `no`.

## Migration rule

No legacy section becomes runtime-authoritative merely by being copied. Each module must declare inputs, outputs, activation conditions, evidence requirements, failure behavior, and tests before entering the executable path.
