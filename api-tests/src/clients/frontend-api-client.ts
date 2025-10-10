// TODO: Frontend does some awkward mapping on this :(
export interface StartRequest {
  _ga?: string;
  authenticated: boolean;
  client_id: string;
  client_name: string;
  cookie_consent?: string;
  cookie_consent_shared: boolean;
  is_identity_verification_required: boolean;
  is_one_login_service: boolean;
  is_smoke_test: boolean;
  previous_govuk_signin_journey_id?: string;
  previous_session_id?: string;
  reauthenticate?: string;
  rp_sector_identifier_host: string;
  scope: string;
  redirect_uri: string;
  requested_credential_strength: string;
  requested_level_of_confidence?: string;
  state: string;
  service_type: string;
  subject_type: string;
}

export interface StartResponse {
  user: UserSessionInfo;
  client?: ClientStartInfo;
}

interface UserSessionInfo {
  upliftRequired: boolean;
  identityRequired: boolean;
  authenticated: boolean;
  cookieConsent?: string;
  gaCrossDomainTrackingId?: string;
  mfaMethodType?: string;
  isBlockedForReauth: boolean;
}

interface ClientStartInfo {
  clientName: string;
  scopes: string[];
  serviceType: string;
  cookieConsentShared: boolean;
  redirectUri: string;
  state: string;
  isOneLoginService: boolean;
}

export interface CheckUserExistsRequest {
  email: string;
}

export interface CheckUserExistsResponse {
  email: string;
  doesUserExist: boolean;
  mfaMethodType: string;
  phoneNumberLastThree: string;
  lockoutInformation: {
    lockType: string;
    mfaMethodType: string;
    lockTTL: number;
    journeyType: string;
  }[];
}

export interface LoginRequest {
  email: string;
  password: string;
  journeyType?: string;
}

export interface LoginResponse {
  redactedPhoneNumber?: string;
  mfaRequired?: boolean;
  latestTermsAndConditionsAccepted?: boolean;
  mfaMethodType?: string;
  mfaMethodVerified?: boolean;
  mfaMethods: object[]; // TODO
  passwordChangeRequired?: boolean;
}

const BASE_URL = "http://localhost:4402";

const getHeaders = (sessionId: string): HeadersInit => ({
  "Content-Type": "application/json",
  "Session-Id": sessionId,
  "Client-Session-Id": "test-client-session-id",
  "Txma-Audit-Encoded": "test-device-data",
});

export const startSession = async (
  body: StartRequest,
  sessionId: string,
): Promise<StartResponse> => {
  const response = await fetch(`${BASE_URL}/start`, {
    method: "POST",
    headers: getHeaders(sessionId),
    body: JSON.stringify(body),
  });

  const responseBody = await response.json();
  if (!response.ok) {
    console.error(responseBody);
    throw new Error("Error response!");
  }

  return responseBody;
};

export const checkUserExists = async (
  body: CheckUserExistsRequest,
  sessionId: string,
): Promise<CheckUserExistsResponse> => {
  const response = await fetch(`${BASE_URL}/user-exists`, {
    method: "POST",
    headers: getHeaders(sessionId),
    body: JSON.stringify(body),
  });

  const responseBody = await response.json();
  if (!response.ok) {
    console.error(responseBody);
    throw new Error("Error response!");
  }

  return responseBody;
};

export const login = async (
  body: LoginRequest,
  sessionId: string,
): Promise<LoginResponse> => {
  const response = await fetch(`${BASE_URL}/login`, {
    method: "POST",
    headers: getHeaders(sessionId),
    body: JSON.stringify(body),
  });

  const responseBody = await response.json();
  if (!response.ok) {
    console.error(responseBody);
    throw new Error("Error response!");
  }

  return responseBody;
};
