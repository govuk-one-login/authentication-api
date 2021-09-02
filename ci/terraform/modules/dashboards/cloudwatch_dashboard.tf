resource "aws_cloudwatch_dashboard" "main" {
  count          = var.use_localstack ? 0 : 1
  dashboard_name = "${var.api_gateway_name}-dashboard"
  dashboard_body = jsonencode(local.template)
}

locals {
  template = {
    start = "-PT336H",
    widgets = [
      {
        height = 6, width = 12, y = 6, x = 0, type = "metric",
        properties = {
          metrics = [
            [
              { expression = "FILL(m1, 0)", label = "", id = "e1", region = "eu-west-2" }
            ],
            [
              "AWS/ApiGateway", "Latency", "ApiName", var.api_gateway_name,
              { id = "m1", visible = false }
            ]
          ],
          "view"    = "timeSeries",
          "stacked" = false,
          "region"  = "eu-west-2",
          "period"  = 21600,
          "stat"    = "Average",
          "title"   = "Latency",
          "yAxis" = {
            "left"  = { "label" = "Millis", "showUnits" = false, "min" = 0 },
            "right" = { "showUnits" = false }
          },
          "setPeriodToTimeRange" = true,
          "legend"               = { "position" = "bottom" },
          "liveData"             = false
        }
      },
      {
        height = 6, width = 12, y = 0, x = 0, type = "metric",
        properties = {
          "metrics" = [
            [
              { expression = "FILL(m1, 0)", label = "", id = "e1", region = "eu-west-2" }
            ],
            [
              "AWS/ApiGateway", "Count", "ApiName", var.api_gateway_name,
              { id = "m1", visible = false }
            ]
          ],
          "view"    = "timeSeries",
          "stacked" = false,
          "region"  = "eu-west-2",
          "period"  = 21600,
          "stat"    = "Sum",
          "title"   = "Requests (sum/hr)",
          "yAxis" = {
            "left"  = { "label" = "Requests", "showUnits" = false },
            "right" = { "showUnits" = false }
          }
        }
      },
      {
        height = 6, width = 12, y = 0, x = 12, type = "metric",
        properties = {
          "metrics" = [
            [
              { expression = "FILL(IF(m2 == 0, 1, 1-(m1/m2)), 1)*100", label = "", id = "e2", region = "eu-west-2", }
            ],
            [
              "AWS/ApiGateway", "5XXError", "ApiName", var.api_gateway_name,
              { id = "m1", visible = false }
            ],
            [
              ".", "Count", ".", ".",
              { id = "m2", visible = false }
            ]
          ],
          "view"    = "timeSeries",
          "stacked" = false,
          "region"  = "eu-west-2",
          "period"  = 21600,
          "stat"    = "Sum",
          "title"   = "Successful requests",
          "yAxis" = {
            "left"  = { "label" = "", "showUnits" = false, "min" = 0, "max" = 100 },
            "right" = { "showUnits" = false }
          },
          "setPeriodToTimeRange" = true,
          "legend"               = { "position" = "bottom" },
          "liveData"             = false
        }
      }
    ]
  }
}
