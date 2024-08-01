export type ClientSession = {
  auth_request_params?: { [key: string]: string[] };
  id_token_hint?: string;
  creation_time: Date;
  effective_vector_of_trust?: {
    credential_trust_level: string;
    level_of_confidence?: string;
  };
  doc_app_subject_id?: string;
  client_name: string;
};
