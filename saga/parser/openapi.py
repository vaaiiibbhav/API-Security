"""OpenAPI specification parser for SAGA framework producing EndpointIR."""

import json
from pathlib import Path
from typing import Any

import yaml

from saga.ir.evidence import Evidence
from saga.ir.models import (
    EndpointIR,
    Parameter,
    RequestBody,
    SecurityMetadata,
)

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


def parse_openapi_spec(spec_source: dict[str, Any] | str | Path) -> list[EndpointIR]:
    """Parse OpenAPI specification into list of canonical EndpointIR models.

    Args:
        spec_source: Dictionary representing OpenAPI spec, JSON/YAML string, or Path.

    Returns:
        List of structured EndpointIR instances extracted from the spec.
    """
    spec: dict[str, Any] = {}

    if isinstance(spec_source, dict):
        spec = spec_source
    elif isinstance(spec_source, str | Path):
        path = Path(spec_source)
        if path.is_file():
            content = path.read_text(encoding="utf-8")
            if path.suffix.lower() in (".yaml", ".yml"):
                spec = yaml.safe_load(content) or {}
            else:
                spec = json.loads(content)
        else:
            try:
                spec = json.loads(str(spec_source))
            except json.JSONDecodeError:
                spec = yaml.safe_load(str(spec_source)) or {}

    endpoints: list[EndpointIR] = []
    paths: dict[str, Any] = spec.get("paths", {})
    global_security: list[dict[str, Any]] = spec.get("security", [])

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in HTTP_METHODS:
            if method not in path_item:
                continue

            op = path_item[method]
            if not isinstance(op, dict):
                continue

            http_method = method.upper()
            handler_name = op.get("operationId", f"{method}_{path.replace('/', '_')}")

            ev = Evidence(
                expression=f"{http_method} {path}",
                extraction_method="openapi_spec",
                confidence_score=1.0,
            )

            raw_params: list[dict[str, Any]] = path_item.get("parameters", []) + op.get(
                "parameters", []
            )
            path_params: list[Parameter] = []
            query_params: list[Parameter] = []

            for p in raw_params:
                if not isinstance(p, dict):
                    continue
                param_name = p.get("name", "")
                param_in = p.get("in", "")
                required = p.get("required", False)
                schema = p.get("schema", {})
                param_type = schema.get("type", "str") if isinstance(schema, dict) else "str"

                model = Parameter(
                    name=param_name,
                    location=param_in,
                    param_type=param_type,
                    required=required,
                    evidence=ev,
                )

                if param_in == "path":
                    path_params.append(model)
                elif param_in == "query":
                    query_params.append(model)

            request_body_model: RequestBody | None = None
            if "requestBody" in op and isinstance(op["requestBody"], dict):
                rb = op["requestBody"]
                content = rb.get("content", {})
                if isinstance(content, dict) and content:
                    content_type = next(iter(content.keys()))
                    media_type = content[content_type]
                    schema = media_type.get("schema", {}) if isinstance(media_type, dict) else {}
                    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
                    req_fields = schema.get("required", []) if isinstance(schema, dict) else []

                    request_body_model = RequestBody(
                        content_type=content_type,
                        schema_name=schema.get("title") or schema.get("$ref"),
                        properties=props,
                        required_fields=req_fields,
                        evidence=ev,
                    )

            op_security = op.get("security", global_security)
            security_schemes: list[str] = []
            requires_auth = False

            if op_security:
                requires_auth = True
                for sec_req in op_security:
                    if isinstance(sec_req, dict):
                        security_schemes.extend(sec_req.keys())

            sec_meta = SecurityMetadata(
                requires_auth=requires_auth,
                security_schemes=list(set(security_schemes)),
            )

            endpoint = EndpointIR(
                http_method=http_method,
                path=path,
                handler_name=handler_name,
                path_parameters=path_params,
                query_parameters=query_params,
                request_body=request_body_model,
                security_metadata=sec_meta,
                evidence=ev,
            )
            endpoints.append(endpoint)

    return endpoints
