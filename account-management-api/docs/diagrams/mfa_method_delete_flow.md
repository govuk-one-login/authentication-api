# MFA Method Delete Flow

This diagram illustrates the flow of the `MFAMethodsDeleteHandler` class, showing the different paths through the code and which audit events are emitted along each path.

```mermaid
flowchart TD
    Start([Start]) --> HandleRequest[handleRequest]
    HandleRequest --> DeleteMFAMethodHandler[deleteMFAMethodHandler]
    
    DeleteMFAMethodHandler --> AddSessionIdToLogs[addSessionIdToLogs]
    AddSessionIdToLogs --> CheckApiEnabled{API Enabled?}
    CheckApiEnabled -->|No| End1([400 Error: MM_API_NOT_AVAILABLE])
    
    CheckApiEnabled -->|Yes| CheckPublicSubjectId{Public Subject ID Empty?}
    CheckPublicSubjectId -->|Yes| End2([400 Error: REQUEST_MISSING_PARAMS])
    
    CheckPublicSubjectId -->|No| CheckMfaIdentifier{MFA Identifier Empty?}
    CheckMfaIdentifier -->|Yes| End3([400 Error: REQUEST_MISSING_PARAMS])
    
    CheckMfaIdentifier -->|No| GetUserProfile[Get User Profile]
    GetUserProfile -->|Not Found| End4([404 Error: USER_NOT_FOUND])
    
    GetUserProfile -->|Found| ValidatePrincipal{Principal Valid?}
    ValidatePrincipal -->|No| End5([401 Error: INVALID_PRINCIPAL])
    
    ValidatePrincipal -->|Yes| DeleteMfaMethod[Delete MFA Method]
    DeleteMfaMethod -->|Fail: Cannot Delete Default| End6([409 Error: CANNOT_DELETE_DEFAULT_MFA])
    DeleteMfaMethod -->|Fail: Non-Migrated User| End7([400 Error: CANNOT_DELETE_MFA_FOR_UNMIGRATED_USER])
    DeleteMfaMethod -->|Fail: Method Not Found| End8([404 Error: MFA_METHOD_NOT_FOUND])
    
    DeleteMfaMethod -->|Success| BuildAuditContext[Build Audit Context]
    BuildAuditContext -->|Fail| End9([401 Error: UNEXPECTED_ACCT_MGMT_ERROR])
    
    BuildAuditContext -->|Success| EmitDeleteCompleted[/Emit AUTH_MFA_METHOD_DELETE_COMPLETED\]
    EmitDeleteCompleted --> SendNotification[Send Notification]
    SendNotification --> End10([204 Success])
    
    style Start fill:#4CAF50,stroke:#388E3C,color:white
    style EmitDeleteCompleted fill:#9370DB,stroke:#7B68EE,color:white
    style End1 fill:#FF5252,stroke:#D32F2F,color:white
    style End2 fill:#FF5252,stroke:#D32F2F,color:white
    style End3 fill:#FF5252,stroke:#D32F2F,color:white
    style End4 fill:#FF5252,stroke:#D32F2F,color:white
    style End5 fill:#FF5252,stroke:#D32F2F,color:white
    style End6 fill:#FF5252,stroke:#D32F2F,color:white
    style End7 fill:#FF5252,stroke:#D32F2F,color:white
    style End8 fill:#FF5252,stroke:#D32F2F,color:white
    style End9 fill:#FF5252,stroke:#D32F2F,color:white
    style End10 fill:#4CAF50,stroke:#388E3C,color:white
```

## Audit Events by User Journey

### Successful Journeys

#### Deleting SMS Backup Method
- **AUTH_MFA_METHOD_DELETE_COMPLETED**: Emitted after successful deletion of SMS backup method
  - Includes metadata: JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_TYPE=SMS
  - Includes metadata: PHONE_NUMBER_COUNTRY_CODE=44
  - Includes phone number in audit context

#### Deleting Auth App Backup Method
- **AUTH_MFA_METHOD_DELETE_COMPLETED**: Emitted after successful deletion of Auth App backup method
  - Includes metadata: JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_TYPE=AUTH_APP

### Failed Journeys

#### API Disabled
- No audit events are emitted when the API is disabled

#### Missing Parameters
- No audit events are emitted when parameters are missing

#### User Not Found
- No audit events are emitted when the user is not found

#### Invalid Principal
- No audit events are emitted when the principal is invalid

#### Cannot Delete Default Method
- No audit events are emitted when attempting to delete a default method

#### Cannot Delete MFA for Non-Migrated User
- No audit events are emitted when attempting to delete MFA for a non-migrated user

#### MFA Method Not Found
- No audit events are emitted when the MFA method is not found