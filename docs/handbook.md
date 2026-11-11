# Zero-Trust Segmentation Lab handbook

By Jason Stys.

Evaluate owner-authored continuity requirements at policy and exception boundaries with a hash-bound review queue.

Evaluate owner-authored continuity requirements at policy and exception boundaries with a hash-bound review queue.

Shows upcoming access changes without granting access, renewing exceptions or assuming transitive trust.

## Read the documentation

| Edition | Audience and contents |
| --- | --- |
| [project-guide.docx](reports/project-guide.docx) | User and developer guide: purpose, current usage, design, boundaries and source references. |

The editable Markdown remains the maintenance source. The Word files are readable editions. See [publication identities and review](reports/publications.json) and the [documentation refresh record](reports/documentation-refresh-2026-11-09.md).

## Current usage and help

[README quick start](../README.md) is the entry point. Use the project-specific guides below before changing inputs, operating modes or deployment assumptions.

### Usage and operations

- [release](release.md)
- [usage](usage.md)

### Design and contracts

- [architecture](architecture.md)
- [contracts](contracts.md)
- [research](research.md)

### Security and validation

- [performance](performance.md)
- [security](security.md)
- [testing](testing.md)
- [validation](validation.md)

## Historical results and reproduction

The reviewed source is [`a685d91f52f89d4d5c5707ec32039b0585ac8fa5`](https://github.com/JasonStys/zero-trust-segmentation-lab/tree/a685d91f52f89d4d5c5707ec32039b0585ac8fa5). The observed functional workflow baseline is `a685d91f52f89d4d5c5707ec32039b0585ac8fa5`; those observations are recorded at `2026-11-10T05:25:40.628667+00:00`. They do not certify an unrun later revision.

- [Detailed recorded validation](reports/continuity-2026-11-09.md)
- [Current Actions](https://github.com/JasonStys/zero-trust-segmentation-lab/actions) records later integration checks separately.
- Preserve dated measurements and follow the existing testing guide to reproduce them; a test-source inventory alone does not establish execution.

## Practical boundaries

- The review previews declared transport access; it does not establish live identity/posture, sessions or service health.
- Continuity requirements are assertions, not policy grants or automatic exception renewal.
- Native enforcement examples operate in isolated lab namespaces, not an automatically deployed production firewall, cloud or device boundary.

## Maintaining these editions

Update the editable usage/design/test documents first. Rebuild and visually review every Word page and workbook tab before replacing an edition; verify the exact binary digests and evidence source in publications.json. Keep account data, logs with secrets, installed-app state and private test stores out of documentation. Source and release assets retain their existing security and licensing boundaries.


## Native offline workbench 1.1.0

[Actual graphical workflows, private owner-local storage, limits and Windows packaging](native-workbench.md). Existing CLI/domain/security gates remain. The native source adapter uses the actual project engines, not prerecorded results or a separate demo app; historical evidence stays bound to its original dated source.
