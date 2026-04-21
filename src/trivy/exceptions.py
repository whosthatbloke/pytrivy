class TargetDoesntExist(Exception):
    """
    To be thrown when searching for an invalid target with the trivy client.
    """

    pass


class VulnerabilityDoesntExist(Exception):
    """
    To be thrown when searching for an invalid vulnerability with the trivy client.
    """

    pass


class LicenseDoesntExist(Exception):
    """
    To be thrown when searching for an invalid license with the trivy client.
    """

    pass


class UnknownImage(Exception):
    """
    To be thrown when using the TrivyClient and the passed image doesn't exist.
    """

    pass


class PackageDoesntExist(Exception):
    """
    To be thrown when searching for an invalid package with the trivy client.
    """

    pass


class TrivyClientNotScanned(Exception):
    """
    To be thrown when a passed TrivyClient has not been scanned.
    """

    pass
