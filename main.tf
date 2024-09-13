# AWS Provider Configuration
provider "aws" {
  region = "us-east-1"  # Replace with your desired region
}

# SES Email Identity (Sender Email)
resource "aws_ses_email_identity" "ses_email_identity" {
  email = "your_verified_email@example.com"  # Replace with your SES verified email
}

# IAM Role for Lambda Function
resource "aws_iam_role" "lambda_execution_role" {
  name = "lambda_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy for Lambda to access CloudTrail, SES, and CloudWatch
resource "aws_iam_policy" "lambda_policy" {
  name = "lambda_policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail",
          "cloudtrail:LookupEvents",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

# Attach Policy to Lambda Role
resource "aws_iam_role_policy_attachment" "lambda_execution_role_policy" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# Create Lambda Function
resource "aws_lambda_function" "cloudtrail_violation_lambda" {
  function_name = "CloudTrailViolationMonitor"
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.9"

  # Path to the Lambda function ZIP file
  filename      = "lambda_function.zip"  # You need to create this ZIP file with your Python code

  # Source code hash to detect changes in the ZIP file
  source_code_hash = filebase64sha256("lambda_function.zip")

  environment {
    variables = {
      SES_SENDER_EMAIL = "your_verified_email@example.com"  # Use your verified SES email
    }
  }
}

# CloudWatch Event Rule to Trigger Lambda Every Hour
resource "aws_cloudwatch_event_rule" "schedule_rule" {
  name        = "cloudtrail_violation_check"
  description = "Triggers Lambda every hour to monitor CloudTrail for violations"
  schedule_expression = "rate(1 hour)"
}

# Attach CloudWatch Event to Lambda
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.schedule_rule.name
  target_id = "lambda_target"
  arn       = aws_lambda_function.cloudtrail_violation_lambda.arn
}

# Allow CloudWatch Events to Trigger Lambda
resource "aws_lambda_permission" "allow_cloudwatch_trigger" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cloudtrail_violation_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule_rule.arn
}

# Outputs
output "lambda_function_arn" {
  value = aws_lambda_function.cloudtrail_violation_lambda.arn
}

output "ses_verified_email" {
  value = aws_ses_email_identity.ses_email_identity.email
}
