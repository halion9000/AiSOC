---
sidebar_position: 2
---

# GraphQL API Reference

AiSOC exposes a GraphQL endpoint alongside the REST API, suitable for flexible data fetching in dashboards and integrations.

## Endpoint

```
POST http://localhost:8000/graphql
```

Headers:
```
Authorization: Bearer <jwt>
Content-Type: application/json
```

## Permissions

GraphQL enforces the same permissions as the REST routes that serve the same data, for a signed-in user's role **and** for an API key's scopes. A field you may not read returns an error that names what is missing (for a key: `API key missing scope: rules:read`), exactly as REST would refuse you:

| Query field | Needs |
| --- | --- |
| `alert`, `alerts` | `alerts:read` |
| `case`, `cases` | `cases:read` |
| `detectionRules` | `rules:read` |
| `connectors` | `connectors:read` |
| `playbooks`, `playbookRuns` | `playbooks:read` |
| `socStats` | `alerts:read` and `cases:read` |

Everything is scoped to **your own tenant**; playbooks and playbook runs are always those of the tenant you are signed in to. Note that an error in a non-null field makes GraphQL return `data: null` for the whole response, so ask for a field you may not read in its own query if you want the others.

The query fields above are the ones the live schema implements. The schema overview further down is broader than what is currently implemented (for example the honeytoken fields, mutations and subscriptions are not part of the live schema); ask the server for its schema rather than relying on that page.

## Interactive Explorer

When running locally, the GraphQL explorer is available at:

[http://localhost:8000/graphql](http://localhost:8000/graphql)

## Schema Overview

### Types

```graphql
type Alert {
  id: ID!
  title: String!
  severity: Severity!
  status: AlertStatus!
  riskScore: Float
  source: String
  tenantId: ID!
  createdAt: DateTime!
  updatedAt: DateTime!
  case: Case
  tags: [String!]!
}

type Case {
  id: ID!
  title: String!
  status: CaseStatus!
  severity: Severity!
  assignee: User
  alerts: [Alert!]!
  timeline: [TimelineEvent!]!
  comments: [Comment!]!
  createdAt: DateTime!
  closedAt: DateTime
}

type UebaAnomaly {
  id: ID!
  entityId: String!
  entityType: EntityType!
  metricName: String!
  observedValue: Float!
  baselineMean: Float!
  baselineStddev: Float!
  zScore: Float!
  severity: Severity!
  detectedAt: DateTime!
}

type Honeytoken {
  id: ID!
  name: String!
  tokenType: TokenType!
  status: TokenStatus!
  createdAt: DateTime!
  lastTouched: DateTime
  touchCount: Int!
}

type PurpleTeamExecution {
  id: ID!
  atomicTestId: String!
  technique: String!
  status: ExecutionStatus!
  platform: String!
  startedAt: DateTime!
  completedAt: DateTime
  findings: [String!]!
}

type ComplianceDashboard {
  framework: String!
  overallScore: Float!
  controlsPassing: Int!
  controlsFailing: Int!
  controlsInReview: Int!
  lastUpdated: DateTime!
}

enum Severity { CRITICAL HIGH MEDIUM LOW INFO }
enum AlertStatus { NEW TRIAGED IN_PROGRESS RESOLVED CLOSED }
enum CaseStatus { OPEN IN_PROGRESS RESOLVED CLOSED }
enum EntityType { USER HOST IP DOMAIN }
enum TokenType { URL FILE AWS_KEY EMAIL }
enum TokenStatus { ACTIVE TRIGGERED REVOKED EXPIRED }
enum ExecutionStatus { PENDING RUNNING SUCCESS FAILED CANCELLED }
```

### Queries

```graphql
type Query {
  # Alerts
  alerts(
    status: AlertStatus
    severity: Severity
    limit: Int = 50
    cursor: String
  ): AlertConnection!

  alert(id: ID!): Alert

  # Cases
  cases(
    status: CaseStatus
    assigneeId: ID
    limit: Int = 50
    cursor: String
  ): CaseConnection!

  case(id: ID!): Case

  # UEBA
  uebaAnomalies(
    entityId: String
    minZScore: Float
    limit: Int = 50
  ): [UebaAnomaly!]!

  # Honeytokens
  honeytokens(status: TokenStatus): [Honeytoken!]!
  honeytokenEvents(tokenId: ID, limit: Int = 100): [HoneytokenEvent!]!

  # Purple Team
  purpleTeamExecutions(status: ExecutionStatus): [PurpleTeamExecution!]!
  attackCoverage: AttackCoverage!

  # Compliance
  complianceDashboard(framework: String!): ComplianceDashboard!
  auditLog(limit: Int = 100, cursor: String): AuditLogConnection!
}
```

### Mutations

```graphql
type Mutation {
  # Cases
  createCase(input: CreateCaseInput!): Case!
  updateCase(id: ID!, input: UpdateCaseInput!): Case!
  addCaseComment(caseId: ID!, body: String!): Comment!

  # Playbooks
  executePlaybook(playbookId: ID!, caseId: ID): PlaybookRun!

  # Honeytokens
  createHoneytoken(input: CreateHoneytokenInput!): Honeytoken!
  revokeHoneytoken(id: ID!): Honeytoken!

  # Purple Team
  runAtomicTest(atomicTestId: String!, targetHost: String): PurpleTeamExecution!
  cancelExecution(id: ID!): PurpleTeamExecution!
}
```

### Subscriptions

```graphql
type Subscription {
  alertCreated: Alert!
  caseUpdated(caseId: ID): Case!
  uebaAnomalyDetected: UebaAnomaly!
  honeytokenTriggered: HoneytokenEvent!
  investigationStep(investigationId: ID!): InvestigationStep!
}
```

## Example Queries

### Recent critical alerts

```graphql
query {
  alerts(severity: CRITICAL, status: NEW, limit: 10) {
    edges {
      node {
        id
        title
        riskScore
        source
        createdAt
      }
    }
  }
}
```

### UEBA anomalies above threshold

```graphql
query {
  uebaAnomalies(minZScore: 3.0) {
    entityId
    metricName
    zScore
    severity
    detectedAt
  }
}
```

### SOC 2 compliance dashboard

```graphql
query {
  complianceDashboard(framework: "soc2") {
    overallScore
    controlsPassing
    controlsFailing
    lastUpdated
  }
}
```
