# syntax=docker/dockerfile:1.4.0
FROM build_image AS builder

ARG TRIVY_VERSION

RUN apt-get update && \ 
    apt-get install -y --no-install-recommends \
    curl
 
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/v${TRIVY_VERSION}/contrib/install.sh | \
    sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

WORKDIR /install
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

FROM runner_image AS runner

ENV PYTHONUNBUFFERED=1

WORKDIR /app/trivy-py

COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /install /usr/local

COPY src/ /app/trivy-py
CMD ["sleep", "2h"]
