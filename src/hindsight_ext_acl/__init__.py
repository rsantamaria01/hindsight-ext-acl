"""Identity-based access control extension for Hindsight.

Enable in the Hindsight API environment::

    HINDSIGHT_API_TENANT_EXTENSION=hindsight_ext_acl:AclTenantExtension
    HINDSIGHT_API_OPERATION_VALIDATOR_EXTENSION=hindsight_ext_acl:AclValidator
    HINDSIGHT_API_TENANT_ACCESS_FILE=/etc/hindsight/access.yaml
    HINDSIGHT_API_TENANT_ROOT_KEY=<key used by the control plane UI>
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__version__ = "0.1.0"

__all__ = ["AclTenantExtension", "AclValidator", "__version__"]

if TYPE_CHECKING:
    from .extension import AclTenantExtension, AclValidator


def __getattr__(name: str) -> Any:
    # Lazy: the CLI (config check, keygen) must work where hindsight_api is not installed.
    if name in ("AclTenantExtension", "AclValidator"):
        from . import extension

        return getattr(extension, name)
    raise AttributeError(name)
