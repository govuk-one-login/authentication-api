import querystring, { ParsedUrlQuery } from "querystring";
import { CredentialTrustLevel } from "../types/credential-trust";

export type RequestParameters = {
  confidence: CredentialTrustLevel;
  reauthenticate?: string;
  authenticated: boolean;
  authenticatedLevel?: CredentialTrustLevel;
};

export const parseRequestParameters = (
  body: string | null,
): RequestParameters => {
  if (body === null) {
    throw new Error("No body");
  }

  const parsedForm = querystring.parse(body);

  const existingAuthentication = getExistingAuthentication(parsedForm);
  return {
    confidence: validateCredentialTrustLevel(parsedForm.level),
    reauthenticate: getReauthenticate(parsedForm),
    authenticated: existingAuthentication.authenticated,
    authenticatedLevel: existingAuthentication.authenticatedLevel,
  };
};

const validateCredentialTrustLevel = (
  level: string | string[] | undefined,
): CredentialTrustLevel => {
  if (level === "Cl" || level === "Cl.Cm") {
    return level;
  }
  throw new Error("Unknown level " + level);
};

const getExistingAuthentication = (form: ParsedUrlQuery) => {
  const authenticated = form.authenticated === "yes";
  const authenticatedLevel = authenticated
    ? validateCredentialTrustLevel(form.authenticatedLevel)
    : undefined;
  return { authenticated, authenticatedLevel };
};

const getReauthenticate = (form: ParsedUrlQuery): string | undefined => {
  if (typeof form.reauthenticate === "string" && form.reauthenticate !== "") {
    return form.reauthenticate;
  }
};
