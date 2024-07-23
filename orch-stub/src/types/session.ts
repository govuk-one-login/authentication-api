export type Session = {
  sessionId: string;
  clientSessions?: string[];
  emailAddress?: string;
  retryCount?: number;
  passwordResetCount?: number;
  codeRequestCountMap?: { string: number };
  currentCredentialStrength?: string;
  isNewAccount?: string;
  authenticated?: boolean;
  processingIdentityAttempts?: number;
  verifiedMfaMethodType?: string;
  internalCommonSubjectIdentifier?: string;
};
