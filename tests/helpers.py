from pathlib import Path

# TODO: Rename these to "...image_name" to make it more clear
MONGODB_2_10_LITERAL: str = "percona/percona-backup-mongodb:2.10.0"
MONGODB_2_11_LITERAL: str = "percona/percona-backup-mongodb:2.11.0"
OPENSEARCH_2_19_LITERAL: str = "docker.io/opensearchproject/opensearch:2.19.4"

RESULTS_BASE_PATH = Path("tests").joinpath("results")
MONGODB_2_10_RESULTS: Path = RESULTS_BASE_PATH.joinpath(
    "results_of_percon_back_mongodb:2.10.0.json"
)
MONGODB_2_11_RESULTS: Path = RESULTS_BASE_PATH.joinpath(
    "results_of_percon_back_mongodb:2.11.0.json"
)
TRAEFIK_CONFIG_RESULTS: Path = RESULTS_BASE_PATH.joinpath(
    "results_of_traefik_config_scan.json"
)
OPENSEARCH_2_19_RESULTS: Path = RESULTS_BASE_PATH.joinpath(
    "results_of_opensearch:2.19.4.json"
)
SBOM_CYCLONEDX_RESULTS: Path = RESULTS_BASE_PATH.joinpath(
    "results_of_sbom_cyclonedx.json"
)
FILESYSTEM_RESULTS: Path = RESULTS_BASE_PATH.joinpath(
    "results_of_filesystem_scan.json"
)
