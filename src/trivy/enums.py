#
# TODO: This should be revamped
#
from enum import Enum


class TrivyScanCommandEnum(Enum):
    Image = "image"
    FileSystem = "fs"
    Config = "config"
    Kubernetes = "kubernetes"
    Repository = "repository"
    RootFS = "rootfs"
    SBOM = "sbom"
    VirtualMachine = "vm"


class SeverityEnum(Enum):
    Critical = "CRITICAL"
    High = "HIGH"
    Medium = "MEDIUM"
    Low = "LOW"
    Unknown = "Unknown"


class TrivyResultsEnum(Enum):
    Severity = "Severity"
    VulnerabilityID = "VulnerabilityID"
    Vulnerabilities = "Vulnerabilities"
    Results = "Results"
    Target = "Target"
    ArtifactName = "ArtifactName"
    ArtifactType = "ArtifactType"
    License = "license"
    LicenseFull = "license-file"
    Licenses = "Licenses"
    Class = "Class"
    Name = "Name"
    Packages = "Packages"
    Description = "Description"
    PkgName = "PkgName"
    InstalledVersion = "InstalledVersion"
    FixedVersion = "FixedVersion"
    Version = "Version"
    Type = "Type"
    ID = "ID"
    Identifier = "Identifier"
    PURL = "PURL"
    DependsOn = "DependsOn"


class SBOMFormatEnum(Enum):
    CycloneDX = "cyclonedx"
    SPDX = "spdx-json"


class TrivyArtifactTypes(Enum):
    Image = "container_image"
    FileSystem = "repository"
