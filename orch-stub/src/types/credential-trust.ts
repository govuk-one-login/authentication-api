export type CredentialTrustLevel = "Cl" | "Cl.Cm";
export type CredentialTrustEnum = "LOW_LEVEL" | "MEDIUM_LEVEL";

export function credentialTrustToEnum(
  trust: CredentialTrustLevel,
): CredentialTrustEnum;
export function credentialTrustToEnum(trust: undefined): undefined;
export function credentialTrustToEnum(
  trust: CredentialTrustLevel | undefined,
): CredentialTrustEnum | undefined;

export function credentialTrustToEnum(trust: CredentialTrustLevel | undefined) {
  switch (trust) {
    case "Cl":
      return "LOW_LEVEL";
    case "Cl.Cm":
      return "MEDIUM_LEVEL";
  }
}
