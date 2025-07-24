import assert from "assert";
import { When, World as CucumberWorld, Then } from "@cucumber/cucumber";
import { checkUserExists, CheckUserExistsResponse, login, LoginResponse, StartRequest, StartResponse, startSession } from "../clients/frontend-api-client.js";

interface World extends CucumberWorld {
  state: string;
  sessionId: string;
  lastResponse?: object;

  email: string;
  mfaMethodType: string;
}

When("I start a new session", async function(this: World) {
  this.state = "test-state";
  this.sessionId = "test-session-id";

  const startRequest: StartRequest = {
    authenticated: false,
    state: this.state,
    requested_credential_strength: "Cl.Cm",
    scope: "openid",
    client_id: "local-client-id",
    client_name: "local-client-name",
    redirect_uri: "http://localhost/redirect",
    service_type: "MANDATORY",
    cookie_consent_shared: false,
    is_smoke_test: false,
    is_one_login_service: false,
    subject_type: "pairwise",
    is_identity_verification_required: false,
    rp_sector_identifier_host: "http://localhost",
  };

  const response = await startSession(startRequest, this.sessionId);

  this.lastResponse = response;
});

Then("the user is not authenticated", function(this: World) {
  assert.equal((this.lastResponse as StartResponse).user.authenticated, false);
});

When("I check that the user {string} exists", async function(this: World, email: string) {
  const response = await checkUserExists({ email }, this.sessionId);
  this.email = response.email;
  this.mfaMethodType = response.mfaMethodType;
  this.lastResponse = response;
});

Then(/the user( does not)? exists?/, function(this: World, doesNot: " does not") {
  assert.equal((this.lastResponse as CheckUserExistsResponse).doesUserExist, !doesNot);
});

Then("uses {string} for MFA", function(this: World, mfaType: string) {
  assert.equal(this.mfaMethodType, mfaType);
});

When("I log in with password {string}", async function(this: World, password: string) {
  const response = await login({ email: this.email, password }, this.sessionId);
  this.lastResponse = response;
});

Then(/the user( does not)? requires? MFA/, function(this: World, doesNot: " does not") {
  assert.equal((this.lastResponse as LoginResponse).mfaRequired, !doesNot);
});
