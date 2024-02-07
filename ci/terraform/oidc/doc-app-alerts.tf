data "aws_cloudwatch_log_group" "doc_app_callback_lambda_log_group" {
  count = var.use_localstack ? 0 : 1
  name  = replace("/aws/lambda/${var.environment}-doc-app-callback-lambda", ".", "")

  depends_on = [
    module.doc-app-callback
  ]
}

resource "aws_cloudwatch_log_metric_filter" "doc_app_callback_metric_filter" {
  count          = var.use_localstack ? 0 : 1
  name           = replace("${var.environment}-doc-app-callback-p1-errors", ".", "")
  pattern        = "{($.level = \"ERROR\")}"
  log_group_name = data.aws_cloudwatch_log_group.doc_app_callback_lambda_log_group[0].name

  metric_transformation {
    name      = replace("${var.environment}-doc-app-error-count", ".", "")
    namespace = "LambdaErrorsNamespace"
    value     = "1"
  }
}