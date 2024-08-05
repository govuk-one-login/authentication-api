import querystring, { ParsedUrlQuery } from "querystring";

export type RequestParameters = {
  confidence: "Cl" | "Cl.Cm";
  reauthenticate?: string;
};

export const parseRequestParameters = (
  body: string | null,
): RequestParameters => {
  if (body === null) {
    throw new Error("No body");
  }

  const parsedForm = querystring.parse(body);
  return {
    confidence: getConfidence(parsedForm),
    reauthenticate: getReauthenticate(parsedForm),
  };
};

const getConfidence = (form: ParsedUrlQuery) => {
  switch (form.level) {
    case "low":
      return "Cl";
    case "medium":
      return "Cl.Cm";
    default:
      throw new Error("Unknown level " + form.level);
  }
};

const getReauthenticate = (form: ParsedUrlQuery): string | undefined => {
  if (typeof form.reauthenticate === "string" && form.reauthenticate !== "") {
    return form.reauthenticate;
  }
};
