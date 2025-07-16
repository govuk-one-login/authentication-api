# MFA Method Update Flow

This diagram illustrates the flow of the `MFAMethodsPutHandler` class, showing the different paths through the code and which audit events are emitted along each path.

```mermaid
flowchart TD
    Start([Start]) --> HandleRequest[handleRequest]
    HandleRequest --> UpdateMFAMethodsHandler[updateMFAMethodsHandler]
    
    UpdateMFAMethodsHandler --> CheckApiEnabled{API Enabled?}
    CheckApiEnabled -->|No| End1([400 Error: MM_API_NOT_AVAILABLE])
    
    CheckApiEnabled -->|Yes| ValidatePutRequest[validatePutRequest]
    ValidatePutRequest -->|Fail: Missing params| End2([400 Error: REQUEST_MISSING_PARAMS])
    ValidatePutRequest -->|Fail: User not found| End3([404 Error: USER_NOT_FOUND])
    ValidatePutRequest -->|Fail: Invalid principal| End4([401 Error: INVALID_PRINCIPAL])
    ValidatePutRequest -->|Fail: JSON error| End5([400 Error: REQUEST_MISSING_PARAMS])
    
    ValidatePutRequest -->|Success| CheckDefaultMethod{Is Default Method?}
    
    CheckDefaultMethod -->|Yes| MigrateMFA[Migrate MFA if required]
    MigrateMFA -->|User not migrated| EmitMigrationAttempted[/Emit AUTH_MFA_METHOD_MIGRATION_ATTEMPTED\]
    EmitMigrationAttempted -->|Migration error| End6([Error from migration])
    EmitMigrationAttempted -->|Migration success| GetMfaMethod[Get MFA Method]
    
    MigrateMFA -->|Already migrated| GetMfaMethod
    CheckDefaultMethod -->|No| GetMfaMethod
    
    GetMfaMethod -->|Fail: Unknown MFA ID| End7([404 Error: MFA_METHOD_NOT_FOUND])
    GetMfaMethod -->|Fail: Other error| End8([500 Error: UNEXPECTED_ACCT_MGMT_ERROR])
    
    GetMfaMethod -->|Success| CheckSmsOtp{Is Default SMS with OTP?}
    CheckSmsOtp -->|Yes| ValidateOtp{Valid OTP?}
    
    ValidateOtp -->|No| EmitInvalidCode[/Emit AUTH_INVALID_CODE_SENT\]
    EmitInvalidCode --> End9([400 Error: INVALID_OTP])
    
    ValidateOtp -->|Yes| CheckSwitch{Is Switch Operation?}
    CheckSmsOtp -->|No| CheckSwitch
    
    CheckSwitch -->|No| EmitCodeVerified[/Emit AUTH_CODE_VERIFIED\]
    EmitCodeVerified -->|Fail| End10([Error from audit event])
    
    CheckSwitch -->|Yes| UpdateMfaMethod[Update MFA Method]
    EmitCodeVerified -->|Success| UpdateMfaMethod
    
    UpdateMfaMethod -->|Fail| HandleUpdateFailure[Handle Update Failure]
    HandleUpdateFailure --> EmitSwitchFailed[/Emit AUTH_MFA_METHOD_SWITCH_FAILED\]
    EmitSwitchFailed --> End11([Error based on failure reason])
    
    UpdateMfaMethod -->|Success| ConvertToResponse[Convert to Response]
    ConvertToResponse -->|Fail| End12([500 Error: UNEXPECTED_ACCT_MGMT_ERROR])
    
    ConvertToResponse -->|Success| CheckUpdateType{Update Type?}
    
    CheckUpdateType -->|Switch| EmitSwitchCompleted[/Emit AUTH_MFA_METHOD_SWITCH_COMPLETED\]
    EmitSwitchCompleted -->|Fail| End13([Error from audit event])
    
    CheckUpdateType -->|Other/None| SendNotification[Send Notification]
    EmitSwitchCompleted -->|Success| SendNotification
    
    SendNotification --> GenerateResponse[Generate Success Response]
    GenerateResponse -->|Success| End14([200 Success])
    GenerateResponse -->|Fail| End15([400 Error: REQUEST_MISSING_PARAMS])
    
    style Start fill:#4CAF50,stroke:#388E3C,color:white
    style EmitInvalidCode fill:#9370DB,stroke:#7B68EE,color:white
    style EmitCodeVerified fill:#9370DB,stroke:#7B68EE,color:white
    style EmitMigrationAttempted fill:#9370DB,stroke:#7B68EE,color:white
    style EmitSwitchFailed fill:#9370DB,stroke:#7B68EE,color:white
    style EmitSwitchCompleted fill:#9370DB,stroke:#7B68EE,color:white
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
    style End15 fill:#FF5252,stroke:#D32F2F,color:white
    style End14 fill:#4CAF50,stroke:#388E3C,color:white
```

## Audit Events by User Journey

### Successful Journeys

#### Updating Default Auth App Method
- **AUTH_CODE_VERIFIED**: Emitted after successful validation
  - Includes metadata: ACCOUNT_RECOVERY=false, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_METHOD=default, MFA_TYPE=AUTH_APP

#### Updating Default SMS Method
- **AUTH_CODE_VERIFIED**: Emitted after successful OTP validation
  - Includes metadata: ACCOUNT_RECOVERY=false, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_METHOD=default, MFA_TYPE=SMS
  - Includes metadata: MFA_CODE_ENTERED, NOTIFICATION_TYPE=MFA_SMS

#### Switching Backup Method to Default
- **AUTH_MFA_METHOD_SWITCH_COMPLETED**: Emitted after successful method switch
  - Includes metadata: JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_TYPE=(type of new default method)

#### Non-Migrated User Updates Method
- **AUTH_MFA_METHOD_MIGRATION_ATTEMPTED**: Emitted during MFA method migration
  - Includes metadata: HAD_PARTIAL, MFA_TYPE=(SMS or AUTH_APP), JOURNEY_TYPE=ACCOUNT_MANAGEMENT, MIGRATION_SUCCEEDED=true
  - Includes metadata: PHONE_NUMBER_COUNTRY_CODE=(country code) (for SMS methods)
- **AUTH_CODE_VERIFIED**: Emitted after successful validation
  - Includes metadata: ACCOUNT_RECOVERY=false, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_METHOD=default, MFA_TYPE=(method type)

### Failed Journeys

#### Invalid OTP (SMS Method Only)
- **AUTH_INVALID_CODE_SENT**: Emitted when an invalid OTP code is provided
  - Includes metadata: MFA_METHOD=default, JOURNEY_TYPE=ACCOUNT_MANAGEMENT

#### Method Update Failure
- **AUTH_CODE_VERIFIED**: Emitted after successful validation
  - Includes metadata: ACCOUNT_RECOVERY=false, JOURNEY_TYPE=ACCOUNT_MANAGEMENT
  - Includes metadata: MFA_METHOD=(priority), MFA_TYPE=(method type)
- **AUTH_MFA_METHOD_SWITCH_FAILED**: Emitted when switching methods fails
  - Only emitted for SWITCHED_MFA_METHODS update type with UNEXPECTED_ERROR failure

#### Migration Failure (Non-Migrated User)
- **AUTH_MFA_METHOD_MIGRATION_ATTEMPTED**: Emitted during MFA method migration
  - Includes metadata: HAD_PARTIAL, MFA_TYPE=(SMS or AUTH_APP), JOURNEY_TYPE=ACCOUNT_MANAGEMENT, MIGRATION_SUCCEEDED=false
  - Includes metadata: PHONE_NUMBER_COUNTRY_CODE=(country code) (for SMS methods)