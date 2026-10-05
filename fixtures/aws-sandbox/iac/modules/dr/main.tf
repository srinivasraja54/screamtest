# Regional failover. Only exercised during DR drills and real incidents.

data "aws_iam_role" "failover" {
  name = "dr-failover-role"
}

resource "aws_lambda_function" "failover" {
  function_name = "regional-failover"
  role          = data.aws_iam_role.failover.arn
  handler       = "failover.handler"
  runtime       = "python3.12"
  filename      = "failover.zip"
}
