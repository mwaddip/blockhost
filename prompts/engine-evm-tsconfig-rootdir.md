Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.

---

# Engine-evm: fix `TS5011` in CI Hardhat test job

## Observable problem

CI `Engine Tests (Hardhat)` fails with:

```
error TS5011: The common source directory of 'tsconfig.json' is './test'.
The 'rootDir' setting must be explicitly set to this or another path to adjust your output's file layout.
```

Reproducible with `npm test` (which runs `hardhat test`).

## Target state

`tsconfig.json` explicitly declares `rootDir` so Hardhat's TypeScript compilation doesn't infer it from the first source file it encounters. The repo has files at `./contracts/`, `./test/`, `./scripts/`, plus `hardhat.config.ts` at the root — TS should see the whole repo as the source root.

Minimal fix: add `"rootDir": "."` to `compilerOptions`. You may also add an explicit `include` array if that suits the project better — your call.

Don't change unrelated config fields (target, module, strict, etc.).

## Verification

1. `npm test` passes locally (or at least gets past the TS compile phase).
2. `npx tsc --noEmit` shows no TS5011.
3. Hardhat tests actually run — contracts compile, test suite executes.

## Deliverables

1. `tsconfig.json` change
2. Commit to main, push
3. Report commit hash

Single commit, no version bump.
