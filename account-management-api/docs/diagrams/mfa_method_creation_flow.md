# MFA Method Creation Flow

This diagram illustrates the flow of the `MFAMethodsCreateHandler` class, showing the different paths through the code and which audit events are emitted along each path.

```mermaid
flowchart TD
    Start([Start]) --> HandleRequest[handleRequest]
    HandleRequest --> MfaMethodsHandler[mfaMethodsHandler]
    
    MfaMethodsHandler --> GuardConditions{Check Guard Conditions}
    GuardConditions -->|Fail: API disabled| End1([400 Error])
    GuardConditions -->|Fail: Missing subject| End2([400 Error])
    GuardConditions -->|Fail: User not found| End3([404 Error])
    GuardConditions -->|Fail: Invalid principal| End4([401 Error])
    
    GuardConditions -->|Pass| BuildAuditContext[Build Audit Context]
    BuildAuditContext -->|Fail| End5([401 Error])
    
    BuildAuditContext -->|Success| ValidateRequest[Validate Request]
    ValidateRequest -->|Fail: Invalid JSON| End6([400 Error])
    ValidateRequest -->|Fail: Default MFA exists| End7([400 Error])
    
    ValidateRequest -->|Fail: Invalid Phone Number| EmitAddFailedPhone[/Emit AUTH_MFA_METHOD_ADD_FAILED\]
    EmitAddFailedPhone --> End19([400 Error: INVALID_PHONE_NUMBER])
    
    ValidateRequest -->|Fail: Invalid OTP| EmitInvalidCode[/Emit AUTH_INVALID_CODE_SENT\]
    EmitInvalidCode --> End8([400 Error])
    
    ValidateRequest -->|Success| EmitCodeVerified[/Emit AUTH_CODE_VERIFIED\]
    EmitCodeVerified -->|Fail| End9([500 Error])
    
    EmitCodeVerified -->|Success| MigrateMFA[Migrate MFA if required]
    MigrateMFA -->|Migration error| End10([Error from migration])
    
    MigrateMFA -->|Success/Not required| AddBackupMFA[Add Backup MFA]
    AddBackupMFA -->|Fail| UpdateAuditContext[Update Audit Context for Failure]
    UpdateAuditContext -->|Fail| End11([500 Error])
    UpdateAuditContext -->|Success| EmitAddFailed[/Emit AUTH_MFA_METHOD_ADD_FAILED\]
    EmitAddFailed --> HandleFailure[Handle Failure Based on Reason]
    HandleFailure --> End12([400 Error with specific reason])
    
    AddBackupMFA -->|Success| CreateResponse[Create MFA Method Response]
    CreateResponse -->|Fail| EmitAddFailedResponse[/Emit AUTH_MFA_METHOD_ADD_FAILED\]
    EmitAddFailedResponse -->|Fail| End13([500 Error])
    EmitAddFailedResponse -->|Success| End14([500 Error - Unexpected])
    
    CreateResponse -->|Success| UpdateAuditContextSuccess[Update Audit Context with MFA Type]
    UpdateAuditContextSuccess --> EmitAddCompleted[/Emit AUTH_MFA_METHOD_ADD_COMPLETED\]
    EmitAddCompleted -->|Fail| End15([500 Error])
    
    EmitAddCompleted -->|Success| SendNotification[Send Notification]
    SendNotification -->|Fail| End16([500 Error - Unexpected])
    
    SendNotification -->|Success| IncrementMetrics[Increment Metrics]
    IncrementMetrics --> GenerateResponse[Generate Success Response]
    GenerateResponse -->|Fail| End17([500 Error - Unexpected])
    GenerateResponse -->|Success| End18([200 Success])
    
    style Start fill:#4CAF50,stroke:#388E3C,color:white
    style EmitInvalidCode fill:#9370DB,stroke:#7B68EE,color:white
    style EmitCodeVerified fill:#9370DB,stroke:#7B68EE,color:white
    style EmitAddFailed fill:#9370DB,stroke:#7B68EE,color:white
    style EmitAddFailedResponse fill:#9370DB,stroke:#7B68EE,color:white
    style EmitAddCompleted fill:#9370DB,stroke:#7B68EE,color:white
    style EmitAddFailedPhone fill:#9370DB,stroke:#7B68EE,color:white
    style End1 fill:#FF5252,stroke:#D32F2F,color:white
    style End2 fill:#FF5252,stroke:#D32F2F,color:white
    style End3 fill:#FF5252,stroke:#D32F2F,color:white
    style End4 fill:#FF5252,stroke:#D32F2F,color:white
    style End5 fill:#FF5252,stroke:#D32F2F,color:white
    style End6 fill:#FF5252,stroke:#D32F2F,color:white
    style End7 fill:#FF5252,stroke:#D32F2F,color:white
    style End8 fill:#FF5252,stroke:#D32F2F,color:white
    style End9 fill:#FF5252,stroke:#D32F2F,color:white
    style End10 fill:#FF5252,stroke:#D32F2F,color:white
    style End11 fill:#FF5252,stroke:#D32F2F,color:white
    style End12 fill:#FF5252,stroke:#D32F2F,color:white
    style End13 fill:#FF5252,stroke:#D32F2F,color:white
    style End14 fill:#FF5252,stroke:#D32F2F,color:white
    style End15 fill:#FF5252,stroke:#D32F2F,color:white
    style End16 fill:#FF5252,stroke:#D32F2F,color:white
    style End17 fill:#FF5252,stroke:#D32F2F,color:white
    style End18 fill:#4CAF50,stroke:#388E3C,color:white
    style End19 fill:#FF5252,stroke:#D32F2F,color:white
```

## Audit Events by User Journey

### Successful MFA Method Creation

#### Non-Migrated User Adds SMS Method
- **AUTH_CODE_VERIFIED**: Emitted after successful OTP validation
  - Includes metadata: MFA_CODE_ENTERED, NOTIFICATION_TYPE=MFA_SMS, ACCOUNT_RECOVERY=false, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_METHOD=backup, MFA_TYPE=SMS
- **AUTH_MFA_METHOD_MIGRATION_ATTEMPTED**: Emitted during MFA method migration
  - Includes metadata: JOURNEY_TYPE=ACCOUNT_MANAGEMENT
- **AUTH_MFA_METHOD_ADD_COMPLETED**: Emitted after MFA method is successfully added
  - Includes metadata: MFA_TYPE=SMS, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes phone number in audit context

#### Migrated User Adds SMS Method
- **AUTH_CODE_VERIFIED**: Emitted after successful OTP validation
  - Includes metadata: MFA_CODE_ENTERED, NOTIFICATION_TYPE=MFA_SMS, ACCOUNT_RECOVERY=false, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_METHOD=backup, MFA_TYPE=SMS
- **AUTH_MFA_METHOD_ADD_COMPLETED**: Emitted after MFA method is successfully added
  - Includes metadata: MFA_TYPE=SMS, JOURNEY_TYPE=ACCOUNT_MANAGEMENT

#### Non-Migrated User Adds Auth App Method
- **AUTH_CODE_VERIFIED**: Emitted after successful validation
  - Includes metadata: ACCOUNT_RECOVERY=false, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_METHOD=backup, MFA_TYPE=AUTH_APP
- **AUTH_MFA_METHOD_MIGRATION_ATTEMPTED**: Emitted during MFA method migration
  - Includes metadata: JOURNEY_TYPE=ACCOUNT_MANAGEMENT
- **AUTH_MFA_METHOD_ADD_COMPLETED**: Emitted after MFA method is successfully added
  - Includes metadata: MFA_TYPE=AUTH_APP, JOURNEY_TYPE=ACCOUNT_MANAGEMENT

#### Migrated User Adds Auth App Method
- **AUTH_CODE_VERIFIED**: Emitted after successful validation
  - Includes metadata: ACCOUNT_RECOVERY=false, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_METHOD=backup, MFA_TYPE=AUTH_APP
- **AUTH_MFA_METHOD_ADD_COMPLETED**: Emitted after MFA method is successfully added
  - Includes metadata: MFA_TYPE=AUTH_APP, JOURNEY_TYPE=ACCOUNT_MANAGEMENT

### Failed Journeys

#### Invalid Phone Number (SMS Method Only)
- **AUTH_MFA_METHOD_ADD_FAILED**: Emitted when an invalid phone number is provided
  - Includes metadata: MFA_METHOD=default, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_TYPE=(from default method)

#### Invalid OTP (SMS Method Only)
- **AUTH_INVALID_CODE_SENT**: Emitted when an invalid OTP code is provided
  - Includes metadata: MFA_METHOD=backup, JOURNEY_TYPE=ACCOUNT_MANAGEMENT

#### Auth App Already Exists (Migrated User)
- **AUTH_CODE_VERIFIED**: Emitted after successful validation
  - Includes metadata: ACCOUNT_RECOVERY=false, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_METHOD=backup, MFA_TYPE=AUTH_APP
- **AUTH_MFA_METHOD_ADD_FAILED**: Emitted when adding backup Auth App method fails
  - Includes metadata: MFA_TYPE=AUTH_APP, MFA_METHOD=default, JOURNEY_TYPE=ACCOUNT_MANAGEMENT

#### Auth App Already Exists (Non-Migrated User)
- **AUTH_CODE_VERIFIED**: Emitted after successful validation
  - Includes metadata: ACCOUNT_RECOVERY=false, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_METHOD=backup, MFA_TYPE=AUTH_APP
- **AUTH_MFA_METHOD_MIGRATION_ATTEMPTED**: Emitted during MFA method migration
  - Includes metadata: JOURNEY_TYPE=ACCOUNT_MANAGEMENT
- **AUTH_MFA_METHOD_ADD_FAILED**: Emitted when adding backup Auth App method fails
  - Includes metadata: MFA_TYPE=AUTH_APP, MFA_METHOD=default, JOURNEY_TYPE=ACCOUNT_MANAGEMENT