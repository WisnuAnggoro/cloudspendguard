resource "aws_db_instance" "a" {
  identifier              = "eval-a"
  engine                  = "postgres"
  instance_class          = "db.t3.medium"
  allocated_storage       = 20
  storage_encrypted       = false
  publicly_accessible     = false
  username                = "admin"
  password                = "placeholder-not-a-secret"
  skip_final_snapshot     = true
}

resource "aws_db_instance" "b" {
  identifier              = "eval-b"
  engine                  = "postgres"
  instance_class          = "db.t3.medium"
  allocated_storage       = 20
  storage_encrypted       = true
  publicly_accessible     = true
  username                = "admin"
  password                = "placeholder-not-a-secret"
  skip_final_snapshot     = true
}

resource "aws_db_instance" "c" {
  identifier              = "eval-c"
  engine                  = "postgres"
  instance_class          = "db.t3.medium"
  allocated_storage       = 20
  storage_encrypted       = false
  publicly_accessible     = true
  username                = "admin"
  password                = "placeholder-not-a-secret"
  skip_final_snapshot     = true
}

resource "aws_db_instance" "d" {
  identifier              = "eval-d"
  engine                  = "postgres"
  instance_class          = "db.t3.medium"
  allocated_storage       = 20
  storage_encrypted       = true
  publicly_accessible     = false
  username                = "admin"
  password                = "placeholder-not-a-secret"
  skip_final_snapshot     = true
}

resource "aws_db_instance" "e" {
  identifier              = "eval-e"
  engine                  = "postgres"
  instance_class          = "db.t3.medium"
  allocated_storage       = 20
  storage_encrypted       = true
  publicly_accessible     = false
  username                = "admin"
  password                = "placeholder-not-a-secret"
  skip_final_snapshot     = true
}

resource "aws_db_instance" "f" {
  identifier              = "eval-f"
  engine                  = "postgres"
  instance_class          = "db.t3.medium"
  allocated_storage       = 20
  storage_encrypted       = false
  publicly_accessible     = false
  username                = "admin"
  password                = "placeholder-not-a-secret"
  skip_final_snapshot     = true
}
