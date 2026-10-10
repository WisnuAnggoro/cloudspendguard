resource "aws_iam_policy" "admin" {
  name   = "eval-admin"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_role_policy" "admin_list" {
  name   = "eval-admin_list"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["*"], Resource = ["*"] }]
  })
}

resource "aws_iam_policy" "s3_read" {
  name   = "eval-s3_read"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "arn:aws:s3:::eval-bucket/*" }]
  })
}

resource "aws_iam_policy" "deny_all" {
  name   = "eval-deny_all"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_policy" "s3_wild" {
  name   = "eval-s3_wild"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }]
  })
}

data "aws_iam_policy_document" "admin_doc" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "admin_via_data" {
  name   = "eval-admin-via-data"
  policy = data.aws_iam_policy_document.admin_doc.json
}
