# Fix verification

Apply the three-anchor rule: compare the original bug anchor, the changed implementation anchor, and the verification anchor. Re-read the fix location, confirm the claimed failure path is removed, scan in-scope siblings, and use a focused test or probe where available.

Comments, changelog text, broad test-suite success, or a nearby edit do not prove the fix. Missing anchors or unresolved sibling instances block `HG-FV`.
