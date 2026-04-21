variable PYTHON_VERSION {
  default = "3.13.11"
}

variable TRIVY_VERSION {
  default = "0.68.2"
}

variable TAG {
  default = "latest"
}

# group targets for easier execution
group "default" {
  targets = ["app"]
}

# the primary build target
target "app" {
  args = {
    TRIVY_VERSION  = "${TRIVY_VERSION}"
  }

  contexts = {
    "build_image" = "docker-image://python:${PYTHON_VERSION}-slim"
    "runner_image" =  "docker-image://python:${PYTHON_VERSION}-slim"
  } 

  context = "."
  dockerfile = "docker/Dockerfile"
  tags = ["trivy-py:${TAG}"]
}