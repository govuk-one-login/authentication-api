export type ClientSession = {
  authRequestParams?: { string: string[] };
  idTokenHint?: string;
  creationTime: Date;
  effectiveVectorOfTrust?: string;
  docAppSubjectId?: string;
  clientName: string;
};
