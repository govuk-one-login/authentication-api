# MFA Method Retrieve Flow

This diagram illustrates the flow of the `MFAMethodsRetrieveHandler` class, showing the different paths through the code and which audit events are emitted along each path.

```mermaid
flowchart TD
    Start([Start]) --> HandleRequest[handleRequest]
    HandleRequest --> GetMFAMethodsHandler[getMFAMethodsHandler]
    
    GetMFAMethodsHandler --> AddSessionIdToLogs[addSessionIdToLogs]
    AddSessionIdToLogs --> CheckApiEnabled{API Enabled?}
    CheckApiEnabled -->|No| End1([400 Error: MM_API_NOT_AVAILABLE])
    
    CheckApiEnabled -->|Yes| CheckPublicSubjectId{Public Subject ID Empty?}
    CheckPublicSubjectId -->|Yes| End2([400 Error: USER_NOT_FOUND])
    
    CheckPublicSubjectId -->|No| GetUserProfile[Get User Profile]
    GetUserProfile -->|Not Found| End3([404 Error: USER_NOT_FOUND])
    
    GetUserProfile -->|Found| ValidatePrincipal{Principal Valid?}
    ValidatePrincipal -->|No| End4([401 Error: INVALID_PRINCIPAL])
    
    ValidatePrincipal -->|Yes| GetMfaMethods[Get MFA Methods]
    GetMfaMethods -->|Fail: Auth App MFA ID Error| End5([500 Error: AUTH_APP_MFA_ID_ERROR])
    GetMfaMethods -->|Fail: Account Does Not Exist| End6([500 Error: ACCT_DOES_NOT_EXIST])
    GetMfaMethods -->|Fail: MFA Method Not Found| End7([500 Error: MFA_METHOD_NOT_FOUND])
    
    GetMfaMethods -->|Success| ConvertToResponse[Convert to Response]
    ConvertToResponse -->|Fail| End8([500 Error: MFA_METHODS_RETRIEVAL_ERROR])
    
    ConvertToResponse -->|Success| SerializeResponse[Serialize Response]
    SerializeResponse --> GenerateResponse[Generate Success Response]
    GenerateResponse --> End9([200 Success])
    
    style Start fill:#4CAF50,stroke:#388E3C,color:white
    style End1 fill:#FF5252,stroke:#D32F2F,color:white
    style End2 fill:#FF5252,stroke:#D32F2F,color:white
    style End3 fill:#FF5252,stroke:#D32F2F,color:white
    style End4 fill:#FF5252,stroke:#D32F2F,color:white
    style End5 fill:#FF5252,stroke:#D32F2F,color:white
    style End6 fill:#FF5252,stroke:#D32F2F,color:white
    style End7 fill:#FF5252,stroke:#D32F2F,color:white
    style End8 fill:#FF5252,stroke:#D32F2F,color:white
    style End9 fill:#4CAF50,stroke:#388E3C,color:white
```

## Audit Events by User Journey

After analyzing the code and integration tests, it appears that the `MFAMethodsRetrieveHandler` class does not emit any audit events. This handler is focused on retrieving MFA methods for a user and does not perform any operations that would require auditing.

### Successful Journeys

#### Retrieving MFA Methods
- No audit events are emitted during the retrieval of MFA methods

### Failed Journeys

#### API Disabled
- No audit events are emitted when the API is disabled

#### User Not Found
- No audit events are emitted when the user is not found

#### Invalid Principal
- No audit events are emitted when the principal is invalid

#### MFA Method Retrieval Failure
- No audit events are emitted when MFA method retrieval fails