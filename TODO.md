## People present 05/02/2024
- Ayo
- Aidan
- Dan
- Gwyn
- Dom


# 19/02/2024
## People present
- Mark
- Michael
- Ayo
- Aidan

# 26/02/2024
## People present
- Aidan
- Ayo
- Alex
- Mark
- Michael

# 04/03/2024
## People present
- Aidan
- Becka
- Ayo
- Mark

## TODO
- Create a separate test that verifies no interactions with account modifiers service
- Verify code storage service gets and deletes OTP code

- NEXT SESSION RESUME POINT: Add submitAuditEvent to EmailCodeProcessor and update test with values instead of unknown
- Make sure EmailCodeProcessor class contains audit service logic, checks for TestClient
- Parametrize shouldReturnNullWhenCorrectEmailCodeProcessed test to test for different notification types (VERIFY_CHANGE_HOW_GET_SECURITY_CODES, RESET_PASSWORD_WITH_CODE)
- Make sure EmailCodeProcessorTest test for both test client and regular client
- Add unit tests against EmailCodeProcessor
- Investigate second metadata pair "account-recovery" shouldReturnNullWhenCorrectEmailCodeProcessed
- Identify the test in the VerifyCodeHandler that are email related
- 
- 
  uk/gov/di/authentication/frontendapi/lambda/VerifyCodeHandlerEmailTest.java:182
- Check that email notification journey types can be accepted in the new processor

- Rename VerifyMfaCodeHandler
