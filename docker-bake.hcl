# Diatreme builds the image from this file when it exists. Both architectures, because the
# CronJob may land on arm64 nodes as well as amd64 ones.
variable "VERSION" { default = "latest" }
variable "REGISTRY" { default = "ghcr.io" }
variable "IMAGE_NAME" { default = "magmamoose/docs-distributor" }
variable "PLATFORMS" { default = "linux/amd64,linux/arm64" }

group "default" {
  targets = ["app"]
}

target "app" {
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = split(",", PLATFORMS)
  tags       = ["${REGISTRY}/${IMAGE_NAME}:${VERSION}"]
}
