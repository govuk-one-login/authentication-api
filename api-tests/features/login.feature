Feature: Login journeys
  Scenario: Login
    # Session start
    When I start a new session
    Then the user is not authenticated

    # Enter email
    When I check that the user "test@account.gov.uk" exists
    Then the user exists
    And uses "SMS" for MFA

    # Enter password
    When I log in with password "Password123"
    Then the user requires MFA

    # Enter MFA
    # When I send an MFA code
    # And I verify the MFA code "456789"
    # Then the code is successfully verified

    # Complete OAuth flow
    # When I get an auth code
    # And I exchange the auth code for an access token
    # And I use the access token to fetch user info
    # Then I get user info for "test@account.gov.uk"
