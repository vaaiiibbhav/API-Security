# SAGA: Framework-Agnostic API Authorization Verification

SAGA is a static API authorization verification framework that lifts web application endpoint implementations (FastAPI, Flask, Django REST Framework) into a Canonical Intermediate Representation ($EndpointIR$), builds typed evidence graphs with control-flow dominance analysis, and performs uncertainty-aware tri-state verification ($\text{PROVEN} / \text{UNPROVEN} / \text{UNKNOWN}$).

## Architecture Overview

```
Framework Source Code (FastAPI / Flask / DRF AST)
                   │
                   ▼
         Framework AST Adapters
                   │
                   ▼
         Canonical EndpointIR (P, O, A, C, Q, S, E)
                   │
                   ▼
       Typed Authorization Graph (MultiDiGraph)
                   │
                   ▼
      Control-Flow Dominance Analysis (AuthPred 支配 Op)
                   │
                   ▼
     Uncertainty-Aware Tri-State Verification Engine
```

## Features

- **Canonical Authorization IR ($EndpointIR$)**: Framework-agnostic normalization of HTTP methods, path templates, authenticated principals, target entities, actions, and authorization predicates.
- **Typed MultiDiGraph & AST Line Provenance**: Maps principal-object relationships, reference parameters, control-flow protection edges, and exact source code line spans (`Evidence`).
- **Control-Flow Dominance Verification**: Verifies that authorization predicates statically dominate sensitive repository and data access operations along all execution paths ($AuthPredicate \dom Operation$).
- **Uncertainty-Aware Tri-State Logic**: Explicitly separates verified authorization ($\text{PROVEN}$) from missing checks ($\text{UNPROVEN}$) and unresolved policy helpers/PDPs ($\text{UNKNOWN}$).

## Installation & Setup

```bash
# Install package in editable mode
pip install -e .

# Run CLI verification
python -m saga.cli scan ./testbed

# Run pytest suite
python -m pytest
```

## License

MIT License.
