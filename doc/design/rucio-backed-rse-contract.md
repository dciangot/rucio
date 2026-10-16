# Rucio-backed RSE contract

**Status: Draft for human review; not an approved API or implementation specification.**

This draft was prepared with AI assistance and requires review and approval by the human contributors before implementation.

## Purpose and scope

A Rucio-backed RSE is a parent-instance storage service whose delegated data is retained and placed by a separate child Rucio instance. The parent selects files and owns the retention obligation it creates. The child owns physical placement, child-level replication, and the retrieval preparation needed to serve those files.

The initial contract covers one parent and one child, file-level delegation, an explicit namespace mapping, a fixed child placement policy, and managed ingress and egress endpoints. Dataset rules may create file-level obligations. Automatic catalogue import, bidirectional synchronization, arbitrary child rule expressions, transparent client uploads/downloads, and recursive delegation are out of scope.

The child REST API is a control plane. Data moves only through configured storage endpoints accessible to the relevant transfer services; a child API URI is not a data-transfer URI.

## Replica and availability semantics

One available parent replica represents one verified child retention obligation and a supported way to retrieve the file. It does not assert that the file has a stable physical location in the child. Any number of child-managed physical replicas still count as exactly one parent replica.

The parent must not report the replica as available merely because a child request was accepted. Availability requires confirmation that:

1. The mapped child DID exists with matching immutable file metadata, including size and the checksums required by the agreed policy.
2. The child retention rule is active and its requested placement policy is satisfied.
3. The child confirms a supported retrieval path can be prepared for the file.
4. The parent has durably recorded the obligation and its child identifiers.

An unreachable child is not proof of data loss. While the child cannot verify health or prepare retrieval, the parent must not claim newly verified availability; an existing obligation should be reported as degraded or unverified, not silently converted into confirmed loss.

## Backend identity and compatibility

The backend concept (`RUCIO`) describes an orchestration and ownership model, not a storage medium. The existing `RSEType` distinguishes `DISK` and `TAPE`; it must not be extended with `RUCIO` solely to identify this service. Nor may a delegated RSE be silently represented as ordinary disk.

The proposed model is a distinct backend capability associated with the RSE, separate from its medium classification. The exact public API, persistence, and configuration representation remains an approval decision. A provisional identifier such as `backend=RUCIO` is illustrative only and is not a committed attribute name or schema.

Before implementation, compatibility review must identify how this capability interacts with:

- RSE expressions and rule placement, so ordinary disk/tape assumptions do not select a delegated RSE incorrectly.
- Replica counting and reporting, so child physical copies never inflate parent replica counts.
- Existing read/write protocol selection, which describes data endpoints and must not perform delegation lifecycle operations.
- Transfer requests and the reaper, which must not treat the child API or a child PFN as an ordinary physical storage target.

The capability must be explicit and opt-in. A Rucio-backed RSE is usable only when its required child, policy, and endpoint configuration is valid.

## Configuration contract

The RSE configuration must identify:

- A stable child-instance identity, child API endpoint, and child VO.
- A dedicated least-privilege service identity and a reference to credentials held outside RSE attributes.
- An explicit, deterministic parent-to-child scope mapping.
- An administrator-controlled child placement and retention policy.
- Managed ingress and egress endpoints and the supported transfer capabilities.
- The capacity delegated to the parent, distinct from physical child consumption.

Secrets and bearer tokens must not be stored in RSE attributes. The parent must not implicitly forward a user's token to the child. Child API endpoints and data endpoints must be explicitly allowlisted. A configured endpoint's network destination must be validated according to the deployment's endpoint-security policy.

## Lifecycle contract

### Store

For each parent operation, the parent creates a durable operation record before starting external side effects. It maps the parent file identity to the child identity using the configured VO and namespace mapping, and records the operation identifier, mapped child DID, child rule identifier when known, and progress.

The parent transfers bytes to the configured ingress endpoint. It then registers or verifies the mapped child DID through the authenticated child API, requests the configured child retention rule, and waits for the child to confirm placement and file metadata. Only after verification may the parent mark its replica available. Temporary ingress protection is released only after the child obligation is verified.

Retries after timeouts or restarts must reuse stable operation and child-obligation identities. If the mapped child DID already exists, immutable metadata must match; a conflict fails the operation and must not overwrite child metadata.

### Read and export

Before an outbound transfer, the parent asks the child to prepare an accessible copy under a temporary export rule or pin. The child returns a usable endpoint from the configured egress capability. The parent transfers from that endpoint and releases the temporary protection when the operation ends, including cancellation and failure paths.

Preparation is asynchronous and retryable. It must not assume that a logical child Rucio URI can be consumed by an ordinary transfer tool.

### Release

The parent releases only the retention ownership it created. Cancellation or deletion must not remove unrelated child rules or child-owned data. When multiple parent rules share a delegated file, the child obligation remains until the last corresponding parent-owned reference is released.

The parent asks the child to remove its identified rule or ownership reference; the child decides whether physical data can be deleted. Parent reaping must never delete an arbitrary child PFN.

### Reconciliation

A reconciliation process compares durable parent obligations with child rule state and replica health. It repairs retryable drift, renews protection before it expires, and reports failures early enough to prevent an unnoticed retention gap. It distinguishes child unavailability from confirmed loss and stops advertising retrieval availability when that availability cannot be verified.

## Correctness and failure requirements

- **Idempotency:** repeated operations, timeouts, and restarts cannot create duplicate parent-owned child obligations or orphaned rules.
- **Identity:** the mapped identity includes child instance, VO, scope, and name. Existing DIDs with conflicting immutable metadata are rejected.
- **Retention:** child protection covers the full parent obligation and is renewed with observable warning before expiry.
- **Ownership:** release is limited to the parent-owned rule/reference and respects shared parent obligations.
- **Availability:** accepted requests are not durability; retrieval is not claimed without a supported, prepared path.
- **Fault handling:** transport/service failure and confirmed data loss are distinct states.
- **Authorization:** child operations use a dedicated least-privilege service identity, explicit endpoint allowlists, and no implicit user-token forwarding.
- **Accounting:** parent logical bytes and delegated capacity are reported separately from child physical consumption.
- **Hierarchy safety:** initial deployments reject a child whose stable instance identity equals the parent. Multi-level delegation is out of scope until cycle detection and a maximum supported depth are specified and validated.

## Integration boundary

The implementation should preserve the client → REST → gateway → core → persistence layering. Public child APIs are used for child DIDs, replicas, and rules; the instances never share databases.

Conveyor may coordinate asynchronous work through a dedicated transfer-tool adapter that maps operation progress to parent request states. Protocol implementations remain responsible for endpoint/data access rather than the delegation lifecycle. Reaper behavior must release delegated ownership rather than delete physical child locations. Durable operation mapping is required for retry and recovery.

## Stage 1 approval checklist

Before implementation begins, reviewers should agree on:

- The replica meaning and the evidence required to mark it available.
- Ownership and shared-reference behavior for retention and release.
- The lifecycle and failure states, including degraded or unverified availability.
- The distinct backend-capability representation and its compatibility with `RSEType`, rule placement, protocols, transfer requests, and reaping.
- Required configuration fields, credential-reference handling, and endpoint trust boundaries.
- The initial one-parent/one-child scope and explicit exclusions above.

This document is a proposal until those decisions are reviewed and approved. Any approved API or schema representation should be recorded separately before implementation.
