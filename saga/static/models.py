"""Re-export canonical IR models from saga.ir for backward compatibility."""

from saga.ir.models import (
    AuthorizationPredicate as ExtractedAuthPredicate,
)
from saga.ir.models import (
    EndpointIR as ASTAnalysisResult,
)
from saga.ir.models import (
    ObjectReference as ExtractedObjectRef,
)
from saga.ir.models import (
    Principal as ExtractedPrincipal,
)

__all__ = [
    "ASTAnalysisResult",
    "ExtractedAuthPredicate",
    "ExtractedObjectRef",
    "ExtractedPrincipal",
]
