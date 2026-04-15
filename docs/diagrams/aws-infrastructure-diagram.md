# AWS Infrastructure Diagram — Authentication System

## Frontend (authentication-frontend)

```
                          ┌─────────────────────────────────┐
                          │           Users / RPs            │
                          └────────────────┬────────────────┘
                                           │
                                           ▼
                              ┌────────────────────────┐
                              │   Route 53 (DNS)       │
                              └───────────┬────────────┘
                                          │
                                          ▼
                          ┌──────────────────────────────┐
                          │  CloudFront Distribution      │
                          │  + WAFv2 WebACL               │
                          │  (rate limiting, IP filtering) │
                          └──────────────┬───────────────┘
                                         │
                                         ▼
                          ┌──────────────────────────────┐
                          │  Application Load Balancer    │
                          │  (ALB) + WAFv2 Association    │
                          │  - HTTPS Listener (443)       │
                          │  - HTTP Listener (80)         │
                          └──────────────┬───────────────┘
                                         │
                          ┌──────────────┴───────────────┐
                          │                              │
                          ▼                              ▼
                ┌──────────────────┐          ┌──────────────────────┐
                │  ECS Cluster     │          │  ECS Service         │
                │  (Fargate)       │          │  (Service Down Page) │
                │                  │          └──────────────────────┘
                │  ┌────────────┐  │
                │  │ Task Def   │  │
                │  │ (Node.js   │  │
                │  │  Express)  │  │
                │  └────────────┘  │
                └────────┬─────────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
              ▼          ▼          ▼
   ┌────────────────┐ ┌──────────┐ ┌──────────────────┐
   │ ElastiCache    │ │ Secrets  │ │ Auth Internal API │
   │ (Redis)        │ │ Manager  │ │ Gateway           │
   │ - Session      │ │ (Redis   │ │ (see below)       │
   │   store        │ │  creds)  │ └────────┬──────────┘
   └────────────────┘ └──────────┘          │
                                            ▼

   Supporting:
   ┌───────────────────┐  ┌───────────────────┐
   │  CloudWatch Logs   │  │  KMS Keys         │
   │  + Subscriptions   │  │  (Log encryption) │
   └───────────────────┘  └───────────────────┘
```

## Auth Internal API (ci/cloudformation/auth — auth-internal-api)

Private VPC-internal API Gateway called by the frontend ECS service.
Defined via OpenAPI spec (AuthInternalApi.yaml), deployed as a SAM Serverless::Api.

```
   ECS Fargate (Frontend)
          │
          │  HTTPS via VPC Endpoint
          ▼
┌──────────────────────────────────────────────────────────────┐
│  API Gateway: Auth Internal API (Private, VPC-internal)      │
│  - Endpoint: PRIVATE (VPC Endpoint restricted)               │
│  - OpenAPI-defined (AuthInternalApi.yaml)                    │
│  - CloudWatch execution & access logs                        │
│  - X-Ray tracing enabled                                     │
├──────────────────────────────────────────────────────────────┤
│  Endpoints (each backed by a Lambda):                        │
│                                                              │
│  /start                    /login                            │
│  /signup                   /verify-code                      │
│  /verify-mfa-code          /send-notification                │
│  /update-profile           /user-exists                      │
│  /reset-password           /reset-password-request           │
│  /mfa                      /account-recovery                 │
│  /processing-identity      /orch-auth-code                   │
│  /account-interventions    /check-reauth-user                │
│  /check-email-fraud-block  /mfa-reset-authorize              │
│  /reverification-result    /id-reverification-state          │
│  /amc-authorize            /amc-callback                     │
│  /start-passkey-assertion  /finish-passkey-assertion         │
│  /.well-known/mfa-reset-jwk.json                             │
│  /.well-known/reverification-jwk.json                        │
│  /.well-known/amc-jwks.json                                  │
│  /.well-known/ad-jwks.json                                   │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Lambda (Java)  │
              │  frontend-api   │
              │  module         │
              └────────┬────────┘
                       │
         ┌─────────────┼──────────────────┐
         │             │                  │
         ▼             ▼                  ▼
   ┌───────────┐ ┌───────────┐  ┌──────────────────┐
   │ DynamoDB   │ │ Redis     │  │ SQS / SNS        │
   │ Tables     │ │ (Session) │  │ (Notifications,  │
   │            │ │           │  │  Audit events)   │
   └───────────┘ └───────────┘  └──────────────────┘
```

## Auth External API (ci/cloudformation/auth — auth-external-api)

Private VPC-internal API Gateway accessed by Orchestration.
Provides token and userinfo endpoints for internal service-to-service communication.

```
   Orchestration Service (internal)
          │
          │  HTTPS via VPC Endpoint
          ▼
┌──────────────────────────────────────────────────────────────┐
│  API Gateway: Auth External API (Private, VPC-internal)      │
│  - Endpoint: PRIVATE (VPC + Orch VPC Endpoint restricted)    │
│  - Policy denies access from outside allowed VPC Endpoints   │
│  - CloudWatch execution & access logs                        │
├──────────────────────────────────────────────────────────────┤
│  Endpoints (each backed by a Lambda):                        │
│                                                              │
│  /token         (TokenHandler)                               │
│  /userinfo      (UserInfoHandler)                            │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Lambda (Java)  │
              │  auth-external  │
              │  -api module    │
              └────────┬────────┘
                       │
         ┌─────────────┼──────────────┐
         │             │              │
         ▼             ▼              ▼
   ┌───────────┐ ┌───────────┐ ┌───────────┐
   │ DynamoDB   │ │ KMS Keys  │ │ SQS       │
   │ (access    │ │ (token    │ │ (TxMA     │
   │  tokens,   │ │  signing) │ │  audit)   │
   │  users)    │ │           │ │           │
   └───────────┘ └───────────┘ └───────────┘
```

## Account Management API (ci/cloudformation/account-management)

Private VPC-internal API Gateway for account management operations (One Login Home Frontend)
Includes a method-management API (OpenAPI-defined) and individual f().

```
   Frontend (Account Management pages)
          │
          │  HTTPS via VPC Endpoint
          ▼
┌──────────────────────────────────────────────────────────────┐
│  API Gateway: Account Management Method Management API       │
│  (Private, VPC-internal)                                     │
│  - Custom authorizer Lambda                                  │
│  - OpenAPI-defined (AccountManagementMMApi.yaml)             │
├──────────────────────────────────────────────────────────────┤
│  Endpoints (each backed by a Lambda):                        │
│                                                              │
│  /authenticate             /delete-account                   │
│  /update-email             /update-password                  │
│  /update-phone-number      /send-otp-notification            │
│  /v1/mfa-methods/{id}      (GET, POST)                       │
│  /v1/mfa-methods/{id}/{mfaId}  (GET, PUT, DELETE)            │
│  /v1/passkeys/{id}         (GET)                             │
│  /v1/passkeys/{id}/{pkId}  (DELETE)                          │
├──────────────────────────────────────────────────────────────┤
│  Additional Lambdas:                                         │
│  - NotificationHandler     - BulkRemoveAccount               │
│  - ManuallyDeleteAccount   - PasskeysDeleteProxy             │
│  - PasskeysRetrieveProxy                                     │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Lambda (Java)  │
              │  account-mgmt   │
              │  module         │
              └────────┬────────┘
                       │
         ┌─────────────┼──────────────┐
         │             │              │
         ▼             ▼              ▼
   ┌───────────┐ ┌───────────┐ ┌───────────────────┐
   │ DynamoDB   │ │ Redis     │ │ SQS Queues        │
   │ Tables     │ │           │ │ - TxMA audit      │
   │            │ │           │ │ - Email notif.    │
   └───────────┘ └───────────┘ │ SNS Topics        │
                               │ - Bulk remove     │
                               └───────────────────┘
```

## Account Data API (ci/cloudformation/account-data)

Private VPC-internal API Gateway for passkey CRUD operations.

```
   Account Management API (internal)
          │
          │  HTTPS via VPC Endpoint
          ▼
┌──────────────────────────────────────────────────────────────┐
│  API Gateway: Account Data API (Private, VPC-internal)       │
│  - OpenAPI-defined (AccountDataApi.yaml)                     │
├──────────────────────────────────────────────────────────────┤
│  Endpoints (each backed by a Lambda):                        │
│                                                              │
│  /accounts/{id}/authenticators/passkeys       (GET, POST)    │
│  /accounts/{id}/authenticators/passkeys/{pkId} (PUT, DELETE) │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Lambda (Java)  │
              │  account-data   │
              │  -api module    │
              └────────┬────────┘
                       │
                       ▼
                 ┌───────────┐
                 │ DynamoDB   │
                 │ (passkeys) │
                 └───────────┘
```

## Delivery Receipts API (ci/cloudformation/auth — delivery-receipts-api)

Regional (public) API Gateway for Notify callback webhooks.

```
   GOV.UK Notify
          │
          │  HTTPS POST
          ▼
┌──────────────────────────────────────────────────────────────┐
│  API Gateway: Delivery Receipts API (REGIONAL, public)       │
│  - /notify-callback (POST)                                   │
│  - CloudWatch access logs                                    │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Lambda (Java)  │
              │  NotifyCallback │
              └─────────────────┘
```

## OIDC API (template.yaml — SAM)

The main SAM template defines the OIDC/orchestration Lambdas and DynamoDB tables.
These Lambdas are wired to the Orchestration API Gateway (Terraform: ci/terraform/oidc).

```
   Relying Parties / Orchestration
          │
          │  HTTPS
          ▼
┌──────────────────────────────────────────────────────────────┐
│  API Gateway: OIDC API  (oidc.<service-domain>)              │
│  - Terraform: ci/terraform/oidc                              │
│  - CloudFront distribution (optional, per environment)       │
│  - Route 53 custom domain                                    │
│  - X-Ray tracing enabled                                     │
├──────────────────────────────────────────────────────────────┤
│  Endpoints (each backed by a SAM Serverless::Function):      │
│                                                              │
│  /authorize               /token (or /token-auth)            │
│  /userinfo                /register                          │
│  /logout                  /callback                          │
│  /ipv-callback            /doc-app-callback                  │
│  /.well-known/*           /jwks                              │
│  /backchannel-logout      /storage-token-jwk.json            │
│  /auth-code               /spot-response (SQS-triggered)     │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Lambda (Java)  │
              │  oidc-api       │
              │  module         │
              └────────┬────────┘
                       │
         ┌─────────────┼──────────────────┐
         │             │                  │
         ▼             ▼                  ▼
   ┌───────────┐ ┌───────────┐  ┌──────────────────┐
   │ DynamoDB   │ │ Redis     │  │ SQS Queues       │
   │ Tables     │ │ (Session) │  │ - BackChannel    │
   │ (SAM)      │ │           │  │   Logout         │
   └───────────┘ └───────────┘  └──────────────────┘
```

## Shared Infrastructure (Terraform: ci/terraform/shared)

```
┌──────────────────────────────────────────────────────────────────────┐
│  DynamoDB Tables                                                     │
│  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────┐ │
│  │ user_credentials  │ │ user_profile     │ │ client_registry      │ │
│  ├──────────────────┤ ├──────────────────┤ ├──────────────────────┤ │
│  │ access_token_store│ │ auth_code_store  │ │ account_modifiers    │ │
│  ├──────────────────┤ ├──────────────────┤ ├──────────────────────┤ │
│  │ common_passwords  │ │ bulk_email_users │ │ email_check_result   │ │
│  ├──────────────────┤ ├──────────────────┤ ├──────────────────────┤ │
│  │ auth_attempt      │ │ auth_session     │ │ id_reverification    │ │
│  ├──────────────────┤ ├──────────────────┤ ├──────────────────────┤ │
│  │ intl_sms_send_cnt │ │ authenticator    │ │                      │ │
│  └──────────────────┘ └──────────────────┘ └──────────────────────┘ │
├──────────────────────────────────────────────────────────────────────┤
│  ElastiCache Redis                                                   │
│  ┌──────────────────────────┐  ┌──────────────────────────┐         │
│  │ sessions_store (API)     │  │ frontend_sessions_store   │         │
│  └──────────────────────────┘  └──────────────────────────┘         │
├──────────────────────────────────────────────────────────────────────┤
│  KMS Keys (20+)                                                      │
│  Token signing, audit payload, DynamoDB encryption, CloudWatch,      │
│  Lambda env vars, events topic, doc app auth, orchestration signing  │
├──────────────────────────────────────────────────────────────────────┤
│  SNS Topics              │  SQS Queues           │  S3 Buckets       │
│  - Events / Audit        │  - Pending email check│  - Smoketest SMS  │
│  - CloudFront alerts     │  - SQS policies       │  - Source code    │
│  - Slack alerts          │                       │                   │
├──────────────────────────┴───────────────────────┴───────────────────┤
│  VPC / Security Groups / SSM Parameter Store / Secrets Manager       │
└──────────────────────────────────────────────────────────────────────┘
```

## End-to-End Flow

```
  User ──► Route 53 ──► CloudFront + WAF ──► ALB ──► ECS Fargate (Node.js Frontend)
                                                          │
                                          ┌───────────────┤
                                          │               │
                                          ▼               ▼
                                  Auth Internal API  (Redis session)
                                  Gateway (Private)
                                      │
                                      ▼
                                 Lambda (Java)
                                  │    │    │
                       ┌──────────┘    │    └──────────┐
                       ▼               ▼               ▼
                   DynamoDB      Redis (Session)    SQS / SNS

  Relying Parties ──► Route 53 ──► CloudFront ──► OIDC API Gateway ──► Lambda
                                                                         │
                                                          ┌──────────────┤
                                                          ▼              ▼
                                                      DynamoDB     SQS / SNS

  Orchestration ──► VPC Endpoint ──► Auth External API (Private) ──► Lambda
  (internal)                         (/token, /userinfo)               │
                                                                       ▼
                                                                   DynamoDB / KMS

  Account Mgmt ──► VPC Endpoint ──► Account Mgmt API (Private) ──► Lambda
  Frontend                          (/authenticate, /update-*,       │
                                     /delete-account, /mfa-methods)  ▼
                                                                 DynamoDB / SQS

  Account Mgmt ──► VPC Endpoint ──► Account Data API (Private) ──► Lambda
  API (internal)                    (/accounts/.../passkeys)         │
                                                                     ▼
                                                                 DynamoDB

  GOV.UK Notify ──► Delivery Receipts API (Regional) ──► NotifyCallback Lambda
```
