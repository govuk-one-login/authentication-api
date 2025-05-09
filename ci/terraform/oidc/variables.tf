variable "oidc_api_lambda_zip_file" {
  default     = "./artifacts/oidc-api.zip"
  description = "Location of the OIDC API Lambda ZIP file"
  type        = string
}

variable "frontend_api_lambda_zip_file" {
  default     = "./artifacts/frontend-api.zip"
  description = "Location of the Frontend API Lambda ZIP file"
  type        = string
}

variable "client_registry_api_lambda_zip_file" {
  default     = "./artifacts/client-registry-api.zip"
  description = "Location of the client registry API Lambda ZIP file"
  type        = string
}

variable "ipv_api_lambda_zip_file" {
  default     = "./artifacts/ipv-api.zip"
  description = "Location of the ipv API Lambda ZIP file"
  type        = string
}

variable "doc_checking_app_api_lambda_zip_file" {
  default     = "./artifacts/doc-checking-app-api.zip"
  description = "Location of the doc checking app API Lambda ZIP file"
  type        = string
}

variable "ipv_p1_alarm_error_threshold" {
  type        = number
  description = "The number of IPV errors raised before generating a Cloudwatch alarm"
  default     = 20
}

variable "ipv_p1_alarm_error_time_period" {
  type        = number
  description = "The time period in seconds for when the IPV errors need to occur"
  default     = 600
}

variable "account_interventions_error_metric_name" {
  type        = string
  description = "The name of the CloudWatch metric which counts Account Intervention Service errors"
  default     = "AISException"
}

variable "account_interventions_p1_alarm_error_threshold" {
  type        = number
  description = "The number of Account Intervention Service errors raised before generating a Cloudwatch alarm"
  default     = 20
}

variable "account_interventions_p1_alarm_error_time_period" {
  type        = number
  description = "The time period in seconds for when the Account Intervention Service errors need to occur"
  default     = 600
}

variable "deployer_role_arn" {
  default     = null
  description = "The name of the AWS role to assume, leave blank when running locally"
  type        = string
}

variable "notify_api_key" {
  description = "The API key required to communicate with Notify"
  type        = string
}

variable "notify_url" {
  type    = string
  default = null
}

variable "notify_test_destinations" {
  type    = string
  default = null
}

variable "notify_template_map" {
  type = map(string)
  default = {
    VERIFY_EMAIL_TEMPLATE_ID                               = "b7dbb02f-941b-4d72-ad64-84cbe5d77c2e"
    VERIFY_PHONE_NUMBER_TEMPLATE_ID                        = "7dd388f1-e029-4fe7-92ff-18496dcb53e9"
    MFA_SMS_TEMPLATE_ID                                    = "97b956c8-9a12-451a-994b-5d51741b63d4"
    RESET_PASSWORD_TEMPLATE_ID                             = "0aaf3ae8-1825-4528-af95-3093eb13fda0"
    PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID                = "052d4e96-e6ca-4da2-b657-5649f28bd6c0"
    ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID               = "a15995f7-94a3-4a1b-9da0-54b1a8b5cc12"
    RESET_PASSWORD_WITH_CODE_TEMPLATE_ID                   = "503a8096-d22e-49dc-9f81-007cad156f01"
    PASSWORD_RESET_CONFIRMATION_SMS_TEMPLATE_ID            = "ee9928fb-c716-4409-acd7-9b93fc02d0f8"
    VERIFY_CHANGE_HOW_GET_SECURITY_CODES_TEMPLATE_ID       = "31259695-e0b8-4c1f-8392-995d5a3b6978"
    CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION_TEMPLATE_ID = "10b2ebeb-16fb-450a-8dc3-5f94d2b7029f"
  }
}

variable "environment" {
  type = string
}

variable "aws_endpoint" {
  type    = string
  default = null
}

variable "aws_dynamodb_endpoint" {
  type    = string
  default = null
}

variable "custom_doc_app_claim_enabled" {
  default = false
  type    = bool
}

variable "terms_and_conditions" {
  type    = string
  default = "1.13"
}

variable "enable_api_gateway_execution_logging" {
  default     = true
  description = "Whether to enable logging of API gateway runs"
  type        = bool
}

variable "enable_api_gateway_execution_request_tracing" {
  default     = false
  description = "Whether to enable capturing of requests/responses from API gateway runs (ONLY ENABLE IN NON-PROD ENVIRONMENTS)"
  type        = bool
}

variable "logging_endpoint_arns" {
  type        = list(string)
  default     = []
  description = "Amazon Resource Name (ARN) for the CSLS endpoints to ship logs to"
}

variable "aws_region" {
  default = "eu-west-2"
  type    = string
}

variable "reset_password_route" {
  type    = string
  default = "reset-password?code="
}

variable "lockout_duration" {
  type    = number
  default = 900
}

variable "lockout_count_ttl" {
  type    = number
  default = 900
}

variable "account_creation_lockout_count_ttl" {
  type    = number
  default = 3600
}

variable "reauth_enter_email_count_ttl" {
  type    = number
  default = 3600
}

variable "reauth_enter_password_count_ttl" {
  type    = number
  default = 3600
}

variable "reauth_enter_auth_app_code_count_ttl" {
  type    = number
  default = 3600
}

variable "reauth_enter_sms_code_count_ttl" {
  type    = number
  default = 3600
}

variable "support_account_creation_count_ttl" {
  default     = false
  type        = bool
  description = "Feature flag which enables using a designated variable for count TTL in the account creation journey"
}

variable "incorrect_password_lockout_count_ttl" {
  type    = number
  default = 7200
}

variable "reduced_lockout_duration" {
  type    = number
  default = 900
}

variable "otp_code_ttl_duration" {
  type    = number
  default = 900
}

variable "email_acct_creation_otp_code_ttl_duration" {
  type    = number
  default = 3600
}

variable "contact_us_link_route" {
  type    = string
  default = "contact-us"
}

variable "gov_uk_accounts_url" {
  type    = string
  default = "https://www.gov.uk/account"
}

variable "shared_state_bucket" {
  type    = string
  default = "digital-identity-dev-tfstate"
}

variable "contra_state_bucket" {
  type = string
}

variable "cloudwatch_log_retention" {
  default     = 30
  type        = number
  description = "The number of day to retain Cloudwatch logs for"
}

variable "lambda_min_concurrency" {
  default     = 0
  type        = number
  description = "The number of lambda instance to keep 'warm'"
}

variable "dlq_alarm_threshold" {
  default     = 1
  type        = number
  description = "The number of messages on a DLQ before a Cloudwatch alarm is generated"
}

variable "notifications_dlq_alarm_threshold" {
  default     = 10
  type        = number
  description = "The number of messages on the notifications DLQ before a Cloudwatch alarm is generated"
}

variable "test_client_verify_email_otp" {
  type = string
}

variable "test_client_verify_phone_number_otp" {
  type = string
}

variable "test_clients_enabled" {
  type    = bool
  default = false
}

variable "client_registry_api_enabled" {
  default = true
  type    = bool
}

variable "evcs_audience" {
  type    = string
  default = "undefined"
}

variable "auth_issuer_claim_for_evcs" {
  type    = string
  default = "undefined"
}

variable "ipv_api_enabled" {
  default = false
  type    = bool
}

variable "ipv_capacity_allowed" {
  default = false
  type    = bool
}

variable "ipv_authorisation_uri" {
  type    = string
  default = "undefined"
}

variable "ipv_authorisation_callback_uri" {
  type    = string
  default = "undefined"
}

variable "ipv_authorisation_client_id" {
  type    = string
  default = "undefined"
}

variable "ipv_audience" {
  type    = string
  default = "undefined"
}

variable "ipv_backend_uri" {
  type    = string
  default = "undefined"
}

variable "ipv_auth_authorize_callback_uri" {
  type    = string
  default = "undefined"
}

variable "ipv_auth_authorize_client_id" {
  type    = string
  default = "undefined"
}

variable "phone_checker_with_retry" {
  type    = bool
  default = true
}

variable "internal_sector_uri" {
  type    = string
  default = "undefined"
}

variable "code_max_retries_increased" {
  type    = number
  default = 999999
}



variable "endpoint_memory_size" {
  default = 1536
  type    = number
}

variable "spot_enabled" {
  default = false
  type    = bool
}

variable "ipv_auth_public_encryption_key" {
  type    = string
  default = "undefined"
}

variable "auth_frontend_public_encryption_key" {
  type        = string
  default     = "undefined"
  description = "Public encryption key which should be used to encrypt JWTs sent to Authentication (frontend)"
}

variable "doc_app_authorisation_uri" {
  type    = string
  default = "undefined"
}

variable "doc_app_authorisation_callback_uri" {
  type    = string
  default = "undefined"
}

variable "doc_app_authorisation_client_id" {
  type    = string
  default = "undefined"
}

variable "doc_app_domain" {
  type    = string
  default = "undefined"
}

variable "doc_app_aud" {
  type        = string
  default     = ""
  description = "Audience to use in calls to DCMAW when doc_app_new_aud_claim_enabled is true"
}

variable "doc_app_new_aud_claim_enabled" {
  type        = bool
  default     = false
  description = "When enabled, use new aud claim to docapp for consistency with IPV Core"
}

variable "doc_app_backend_uri" {
  type        = string
  default     = ""
  description = "The base URL of the Doc App CRI API (to be used with the token endpoint and protected resource)"
}

variable "doc_app_cri_data_endpoint" {
  type        = string
  default     = ""
  description = "The endpoint path to the protected resource on the Doc App CRI (this is appended to the doc_app_backend_uri variable)"
}

variable "doc_app_encryption_key_id" {
  type    = string
  default = "undefined"
}

variable "doc_app_jwks_endpoint" {
  type    = string
  default = "undefined"
}

variable "doc_app_cri_data_v2_endpoint" {
  type    = string
  default = "userinfo/v2"
}

variable "doc_app_rp_client_id" {
  type    = string
  default = "undefined"
}

variable "spot_account_number" {
  type        = string
  default     = "undefined"
  description = "The AWS account number for SPOT"
}

variable "spot_response_queue_arn" {
  type        = string
  default     = "undefined"
  description = "The ARN for the SPOT response queue"
}

variable "spot_response_queue_kms_arn" {
  type        = string
  default     = "undefined"
  description = "The ARN for the KMS key used by the SPOT response queue"
}

variable "performance_tuning" {
  type = map(object({
    memory : number,
    concurrency : number,
    max_concurrency : number,
    scaling_trigger : number,
  }))
  description = "A map of performance tuning parameters per lambda"
  default     = {}
}

variable "lambda_max_concurrency" {
  default = 0
  type    = number
}

variable "scaling_trigger" {
  default = 0.6
  type    = number
}

variable "use_robots_txt" {
  default = true
  type    = bool
}

variable "txma_account_id" {
  default = ""
  type    = string
}

variable "orch_client_id" {
  type    = string
  default = "orchestrationAuth"
}

variable "orch_frontend_api_gateway_integration_enabled" {
  # When this flag is enabled in a particular environment, the corresponding orchestration-frontend flag
  # (OidcApiGatewayIntegrationEnabled) should also be enabled for that environment.
  description = "Flag to enable API Gateway integration with the Orchestration frontend"
  type        = bool
  default     = false
}

variable "orch_openid_configuration_enabled" {
  description = "Flag to enable routing openid configuration traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_doc_app_callback_enabled" {
  description = "Flag to enable routing doc app callback traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_token_enabled" {
  description = "Flag to enable routing token traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_jwks_enabled" {
  description = "Flag to enable routing jwks traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_authorisation_enabled" {
  description = "Flag to enable routing authorisation endpoint traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "auth_spot_response_disabled" {
  description = "Flag to disable routing spot response traffic to the authentication account"
  type        = bool
  default     = false
}

variable "orch_logout_enabled" {
  description = "Flag to enable routing logout traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_ipv_callback_enabled" {
  description = "Flag to enable routing ipv callback traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_register_enabled" {
  description = "Flag to enable routing register traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_authentication_callback_enabled" {
  description = "Flag to enable routing authentication callback traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_auth_code_enabled" {
  description = "Flag to enable routing auth code traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_userinfo_enabled" {
  description = "Flag to enable routing userinfo traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_storage_token_jwk_enabled" {
  description = "Flag to enable routing storage token jwk traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "orch_frontend_enabled" {
  description = "Flag to enable redirecting to orch frontend instead of auth frontend"
  type        = bool
  default     = false
}

variable "orch_ipv_jwks_enabled" {
  description = "Flag to enable routing IPV jwk traffic to the orchestration account"
  type        = bool
  default     = false
}

variable "use_strongly_consistent_reads" {
  default     = false
  description = "Whether to use strongly consistent reads when getting items from DynamoDB"
  type        = bool
}

variable "account_intervention_service_action_enabled" {
  default = false
  type    = bool
}

variable "account_intervention_service_call_enabled" {
  default = false
  type    = bool
}

variable "account_intervention_service_abort_on_error" {
  default = false
  type    = bool
}

variable "account_intervention_service_uri" {
  default = "undefined"
  type    = string
}

variable "account_intervention_service_call_timeout" {
  default     = 3000
  type        = number
  description = "The HTTP Client connection timeout for requests to Account Intervention Service (in milliseconds)."
}

variable "ticf_cri_service_uri" {
  default = "undefined"
  type    = string
}

variable "ticf_cri_service_call_timeout" {
  default     = 2000
  type        = number
  description = "The HTTP Client connection timeout for requests to TICF CRI Service (in milliseconds)."
}

variable "orch_redirect_uri" {
  type        = string
  description = "The redirect URI set by Orchestration in the OAuth2 authorize request to Authentication"
}

variable "authorize_protected_subnet_enabled" {
  description = "Flag to move authorize lambda to protected subnet"
  type        = bool
  default     = false
}

variable "support_email_check_enabled" {
  default     = true
  type        = bool
  description = "Feature flag which toggles the Experian email check on and off"
}

variable "send_storage_token_to_ipv_enabled" {
  default     = false
  type        = bool
  description = "Feature flag which toggles whether signed VC storage token is included as claim in JAR sent to IPV"
}

variable "support_reauth_signout_enabled" {
  default     = false
  type        = bool
  description = "Feature flag which toggles sign-out instead of lockout for reauth journeys"
}

variable "orch_account_id" {
  type    = string
  default = ""
}

variable "is_orch_stubbed" {
  type    = bool
  default = false
}

variable "orch_environment" {
  type    = string
  default = ""
}

variable "orch_session_table_encryption_key_arn" {
  type    = string
  default = ""
}

variable "orch_client_session_table_encryption_key_arn" {
  type    = string
  default = ""
}

variable "orch_identity_credentials_table_encryption_key_arn" {
  type    = string
  default = ""
}

variable "cmk_for_back_channel_logout_enabled" {
  default     = false
  type        = bool
  description = "Feature flag which toggles whether the back channel logout queue is encrypted using CMK"
}

variable "oidc_origin_cloaking_header" {
  type        = string
  description = "Secret header to prove the origin request comes via cloudfront. Set using secrets manager and the read secrets script."
}

variable "previous_oidc_origin_cloaking_header" {
  type        = string
  description = "Used in rotation of the origin cloaking header. Set using secrets manager and the read secrets script."
}

variable "authentication_attempts_service_enabled" {
  type        = bool
  default     = false
  description = "Feature flag to use dynamoDb AuthenticationAttempts table to store OTP code information"
}

variable "call_ticf_cri" {
  type        = bool
  default     = false
  description = "Feature flag to switch on invoking TICF CRI lambda."
}

variable "oidc_cloudfront_enabled" {
  type        = bool
  default     = true
  description = "Feature flag to disable cloudfront in envirometns that don't support it (authdev1 / authdev2)."
}

variable "auth_frontend_api_to_ipv_public_encryption_key" {
  type        = string
  default     = ""
  description = "Public key for IPV"
}

locals {
  default_performance_parameters = {
    memory          = var.endpoint_memory_size
    concurrency     = var.lambda_min_concurrency
    max_concurrency = var.lambda_max_concurrency
    scaling_trigger = var.scaling_trigger
  }
}

variable "frontend_api_fms_tag_value" {
  default     = "authenticationfrontend"
  description = "Tag value to be used for FMS WAF association for frontend API"
  type        = string
}

variable "ipv_jwks_url" {
  type        = string
  default     = ""
  description = "Endpoint to get the IPV JWKS to encrypt and verify JWTs in the MFA reset journey"
}

variable "ipv_auth_public_encryption_key_id" {
  type        = string
  default     = ""
  description = "Key ID for to encrypt JWT to send to IPV"
}

variable "ipv_jwks_call_enabled" {
  type    = bool
  default = false
}
