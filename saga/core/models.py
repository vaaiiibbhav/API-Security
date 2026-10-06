"""Re-export canonical IR models from saga.ir for backward compatibility."""

from saga.ir.models import (
    EndpointIR as Endpoint,
)
from saga.ir.models import (
    ObjectReference as ExtractedObjectRef,
)
from saga.ir.models import (
    Parameter as ParameterModel,
)
from saga.ir.models import (
    Principal as ExtractedPrincipal,
)
from saga.ir.models import (
    RequestBody as RequestBodyModel,
)
from saga.ir.models import (
    SecurityMetadata as SecurityMetadataModel,
)

__all__ = [
    "Endpoint",
    "ExtractedObjectRef",
    "ExtractedPrincipal",
    "ParameterModel",
    "RequestBodyModel",
    "SecurityMetadataModel",
]
