module "dr" {
  source = "./modules/dr"
}

data "aws_iam_role" "payments" {
  name = "payments-api-role"
}

resource "aws_ecs_task_definition" "payments_api" {
  family        = "payments-api"
  task_role_arn = data.aws_iam_role.payments.arn
  container_definitions = jsonencode([{
    name  = "api"
    image = "111122223333.dkr.ecr.eu-west-1.amazonaws.com/payments-api:latest"
  }])
}
