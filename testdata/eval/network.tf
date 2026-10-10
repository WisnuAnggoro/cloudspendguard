resource "aws_vpc" "logged" {
  cidr_block = "10.18.0.0/16"
}


resource "aws_flow_log" "logged" {
  vpc_id               = aws_vpc.logged.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = "arn:aws:logs:eu-west-1:111122223333:log-group:flow"
  iam_role_arn         = "arn:aws:iam::111122223333:role/flow"
}

resource "aws_vpc" "logged2" {
  cidr_block = "10.18.0.0/16"
}


resource "aws_flow_log" "logged2" {
  vpc_id               = aws_vpc.logged2.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = "arn:aws:logs:eu-west-1:111122223333:log-group:flow"
  iam_role_arn         = "arn:aws:iam::111122223333:role/flow"
}

resource "aws_vpc" "silent" {
  cidr_block = "10.18.0.0/16"
}

resource "aws_vpc" "silent2" {
  cidr_block = "10.19.0.0/16"
}
