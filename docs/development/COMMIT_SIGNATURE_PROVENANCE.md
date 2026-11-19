# GitHub commit-signature provenance: PREDICT-SHIELD

**Evidence audit:** GitHub REST API `GET /repos/katlaang/predict-shield/commits`
and `GET /repos/katlaang/predict-shield/commits/{sha}`. Snapshot reviewed
November 18, 2026 (U.S. Central time). The repository history must not be
rewritten merely to change verification badges: doing so changes SHA-1
commit identities and breaks pinned experiment provenance.

## What GitHub verifies

The `commit.verification` field describes a **cryptographic commit
signature**, not whether code works, whether the author performed the
research, or whether experimental claims are correct.

Examples on the default branch at the audit:

| Commit | GitHub verification | Meaning |
| --- | --- | --- |
| `3450d9466d92` (merge PR #111) | `verified=true, reason=valid` | GitHub generated a valid recognized GPG signature for the merge commit |
| `cd88d4a5cdbb` (model file through GitHub connector) | `verified=false, reason=unsigned` | File-content REST API commit had no cryptographic signature |
| `e8af499a5113` (AI rule generator) | `verified=false, reason=unknown_key` | Commit has an SSH signature that GitHub does not recognize as an uploaded, associated signing key |

A successful test run, a verified GitHub-created merge commit, and the
unsigned commits that became its parents are **distinct** facts.
Verifying the merge signature **does not retroactively sign its parents**.

## Future commits: recommended corrective process

1. On a trusted developer machine, generate or select a dedicated SSH
   signing key. Never commit the private key, send it in chat, upload it
   to the repository, or paste it into a public PR.
2. Add the matching **public** key to the correct GitHub account under
   **Settings > SSH and GPG keys > New SSH key**, with **Key type:
   Signing Key** (not only Authentication Key). If the key is already
   registered for authentication, follow GitHub's applicable key-reuse
   rules rather than assuming the authentication registration also
   enables commit verification.
3. Configure signed commits locally, for example:
   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
   git config --global commit.gpgsign true
   ```
   Replace the sample public-key path with the path actually used on
   the trusted machine. Check the associated commit email and GitHub
   verified-email requirements. A key may require additional setup
   depending on the signing environment.
4. Create and push a **new test commit** and inspect GitHub's
   `commit.verification.verified` and `reason`. Do not declare success
   from local `git log --show-signature` alone.
5. Commits made by the repository's connected GitHub file API
   (`create_file`, `update_file`, Git tree/commit endpoints) are **not
   signed by that connector**. A merge executed by GitHub can be signed
   but does not sign its unsigned parent commits. To require every new
   commit to be signed, use a trusted signing-capable Git workflow
   rather than this REST file-edit workflow.
6. Only after routine signing works should maintainers consider a
   protected branch or repository ruleset requiring signed commits.
   Enabling a requirement first could block the existing connector's
   unsigned workflow; verify compatibility before enforcing.

## Experiment integrity is a separate requirement

Keep source commits, release tags, dataset digests, CI run IDs, pinned
models, unmodified negative results, pre-registration and external
validation records. A GitHub Verified badge is **not** an experiment
attestation or independent verification of efficacy.

## Primary references

- GitHub Docs: https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification
- GitHub Docs: https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key
- GitHub Docs: https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account
- GitHub Docs (SSH signing): https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-new-ssh-key-to-your-github-account
