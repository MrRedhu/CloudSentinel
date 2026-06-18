# Dependency layer (anthropic + pydantic, built for the Lambda runtime).
# Built out-of-band before apply:
#   pip install --platform manylinux2014_x86_64 --implementation cp \
#     --python-version 3.12 --only-binary=:all: --target build/layer/python anthropic pydantic
#   (then zip build/layer -> build/layer.zip)
resource "aws_lambda_layer_version" "deps" {
  layer_name          = "${local.name_prefix}-deps"
  filename            = "${path.module}/../build/layer.zip"
  source_code_hash    = filebase64sha256("${path.module}/../build/layer.zip")
  compatible_runtimes = ["python3.12"]
}
