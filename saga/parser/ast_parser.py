"""Python AST route and security discovery converting source code into EndpointIR."""

import ast
import re
from pathlib import Path

from saga.ir.evidence import Evidence
from saga.ir.models import (
    AuthorizationPredicate,
    EndpointIR,
    ObjectReference,
    Parameter,
    PredicateType,
    Principal,
    SecurityMetadata,
)

SUPPORTED_HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


class FastAPIRouteVisitor(ast.NodeVisitor):
    """AST visitor discovering FastAPI route handlers, parameters, and security facts."""

    def __init__(self, file_path: Path | str | None = None) -> None:
        self.file_path = Path(file_path) if file_path else None
        self.endpoints: list[EndpointIR] = []
        self.router_prefixes: dict[str, str] = {}

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track APIRouter(prefix="/...") variable assignments."""
        if isinstance(node.value, ast.Call):
            func = node.value.func
            func_name = ""
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr

            if func_name == "APIRouter":
                prefix = ""
                for kw in node.value.keywords:
                    if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                        prefix = str(kw.value.value)

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.router_prefixes[target.id] = prefix

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Inspect synchronous function definitions for route decorators."""
        self._check_function_node(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Inspect asynchronous function definitions for route decorators."""
        self._check_function_node(node)
        self.generic_visit(node)

    def _check_function_node(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue

            func_node = decorator.func
            if not isinstance(func_node, ast.Attribute):
                continue

            method_name = func_node.attr.lower()
            if method_name not in SUPPORTED_HTTP_METHODS:
                continue

            target_obj = ""
            if isinstance(func_node.value, ast.Name):
                target_obj = func_node.value.id

            route_path = ""
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                route_path = str(decorator.args[0].value)
            else:
                for kw in decorator.keywords:
                    if kw.arg == "path" and isinstance(kw.value, ast.Constant):
                        route_path = str(kw.value.value)

            prefix = self.router_prefixes.get(target_obj, "")
            full_path = (prefix.rstrip("/") + "/" + route_path.lstrip("/")).rstrip("/")
            if not full_path.startswith("/"):
                full_path = "/" + full_path

            ev = Evidence(
                source_file=self.file_path,
                source_line=node.lineno,
                expression=f"@{target_obj}.{method_name}('{route_path}')",
                extraction_method="ast_visitor",
                confidence_score=1.0,
            )

            path_params, query_params, principals = self._extract_parameters(node, route_path, ev)
            sec_meta, predicates = self._analyze_security_body(node, principals, ev)
            objects = self._extract_objects(node, ev)

            endpoint_ir = EndpointIR(
                http_method=method_name.upper(),
                path=full_path,
                handler_name=node.name,
                source_file=self.file_path,
                source_line=node.lineno,
                path_parameters=path_params,
                query_parameters=query_params,
                security_metadata=sec_meta,
                principals=principals,
                objects=objects,
                predicates=predicates,
                evidence=ev,
            )
            self.endpoints.append(endpoint_ir)

    def _extract_parameters(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        route_path: str,
        base_ev: Evidence,
    ) -> tuple[list[Parameter], list[Parameter], list[Principal]]:
        path_params: list[Parameter] = []
        query_params: list[Parameter] = []
        principals: list[Principal] = []

        path_param_names = set(re.findall(r"\{([a-zA-Z0-9_]+)\}", route_path))
        defaults_offset = len(node.args.args) - len(node.args.defaults)

        for idx, arg in enumerate(node.args.args):
            arg_name = arg.arg
            if arg_name in ("self", "cls"):
                continue

            param_type = "str"
            if arg.annotation:
                if isinstance(arg.annotation, ast.Name):
                    param_type = arg.annotation.id
                elif isinstance(arg.annotation, ast.Constant):
                    param_type = str(arg.annotation.value)

            dependency_func = None
            is_dep = False

            if idx >= defaults_offset:
                default_node = node.args.defaults[idx - defaults_offset]
                if isinstance(default_node, ast.Call):
                    func_node = default_node.func
                    if isinstance(func_node, ast.Name) and func_node.id == "Depends":
                        is_dep = True
                        if default_node.args and isinstance(default_node.args[0], ast.Name):
                            dependency_func = default_node.args[0].id

            is_db_dep = arg_name in ("db", "session") or (
                dependency_func is not None and "db" in dependency_func.lower()
            )

            is_principal = (
                "user" in arg_name.lower() or "principal" in arg_name.lower()
            ) and not arg_name.endswith("_id") and not arg_name.endswith("_uuid")

            param_ev = Evidence(
                source_file=self.file_path,
                source_line=node.lineno,
                expression=f"{arg_name}: {param_type}",
                extraction_method="ast_visitor",
            )

            if not is_db_dep and (is_dep or is_principal):
                principals.append(
                    Principal(
                        param_name=arg_name,
                        type_annotation=param_type if param_type != "str" else "User",
                        dependency_func=dependency_func,
                        evidence=param_ev,
                    )
                )

            if arg_name in path_param_names:
                path_params.append(
                    Parameter(
                        name=arg_name,
                        location="path",
                        param_type=param_type,
                        evidence=param_ev,
                    )
                )
            elif not is_dep and not is_db_dep:
                query_params.append(
                    Parameter(
                        name=arg_name,
                        location="query",
                        param_type=param_type,
                        evidence=param_ev,
                    )
                )

        return path_params, query_params, principals


    def _extract_objects(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, base_ev: Evidence
    ) -> list[ObjectReference]:
        objects: list[ObjectReference] = []

        for body_node in ast.walk(node):
            if not isinstance(body_node, ast.Call):
                continue

            func = body_node.func
            ev = Evidence(
                source_file=self.file_path,
                source_line=body_node.lineno,
                expression=ast.unparse(body_node) if hasattr(ast, "unparse") else None,
            )

            if (
                isinstance(func, ast.Attribute)
                and func.attr == "query"
                and body_node.args
                and isinstance(body_node.args[0], ast.Name)
            ):
                entity_name = body_node.args[0].id
                objects.append(
                    ObjectReference(
                        entity_name=entity_name,
                        access_method="query",
                        is_security_sensitive=True,
                        evidence=ev,
                    )
                )

            elif (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and isinstance(func.value, ast.Name)
                and func.value.id not in ("router", "app")
            ):
                entity_name = func.value.id
                objects.append(
                    ObjectReference(
                        entity_name=entity_name,
                        access_method="get",
                        is_security_sensitive=True,
                        evidence=ev,
                    )
                )

        return objects

    def _analyze_security_body(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        principals: list[Principal],
        base_ev: Evidence,
    ) -> tuple[SecurityMetadata, list[AuthorizationPredicate]]:
        auth_deps = [p.dependency_func for p in principals if p.dependency_func]
        requires_auth = len(principals) > 0 or len(auth_deps) > 0
        has_owner_check = False
        has_tenant_check = False
        required_roles: list[str] = []
        predicates: list[AuthorizationPredicate] = []

        for body_node in ast.walk(node):
            if isinstance(body_node, ast.Compare):
                left_str = ast.unparse(body_node.left) if hasattr(ast, "unparse") else ""
                comp_exprs = [
                    ast.unparse(c) for c in body_node.comparators if hasattr(ast, "unparse")
                ]
                if not comp_exprs:
                    continue
                right_str = comp_exprs[0]

                op_str = "=="
                if body_node.ops and type(body_node.ops[0]) is ast.NotEq:
                    op_str = "!="

                all_str = f"{left_str} {op_str} {right_str}"

                # Require predicate comparison against principal or tenant context
                has_user_context = any(
                    ctx in left_str or ctx in right_str
                    for ctx in ("current_user", "principal", "user_context", "tenant_id")
                )
                if not has_user_context:
                    continue

                ev = Evidence(
                    source_file=self.file_path,
                    source_line=body_node.lineno,
                    expression=all_str,
                )

                if "owner_id" in all_str or "user_id" in all_str or "owner" in all_str:
                    has_owner_check = True
                    predicates.append(
                        AuthorizationPredicate(
                            predicate_type=PredicateType.OWNERSHIP,
                            subject_expr=left_str if "current_user" in left_str else right_str,
                            object_expr=right_str if "current_user" in left_str else left_str,
                            operator=op_str,
                            normalized_relation="owns",
                            evidence=ev,
                        )
                    )

                if "tenant_id" in all_str or "tenant" in all_str:
                    has_tenant_check = True
                    predicates.append(
                        AuthorizationPredicate(
                            predicate_type=PredicateType.TENANT,
                            subject_expr=left_str if "current_user" in left_str else right_str,
                            object_expr=right_str if "current_user" in left_str else left_str,
                            operator=op_str,
                            normalized_relation="same_tenant",
                            evidence=ev,
                        )
                    )

            # Check for delegated helper function calls
            # e.g., check_custom_policy(user, doc) or policy.can_access(...)
            elif isinstance(body_node, ast.Call):
                func_name = ""
                if isinstance(body_node.func, ast.Name):
                    func_name = body_node.func.id
                elif isinstance(body_node.func, ast.Attribute):
                    func_name = body_node.func.attr

                is_delegated_call = func_name and any(
                    kw in func_name.lower()
                    for kw in ("policy", "can_access", "check_custom", "verify_access")
                )
                if is_delegated_call:
                    ev = Evidence(
                        source_file=self.file_path,
                        source_line=body_node.lineno,
                        expression=ast.unparse(body_node) if hasattr(ast, "unparse") else func_name,
                    )

                    predicates.append(
                        AuthorizationPredicate(
                            predicate_type=PredicateType.DELEGATED,
                            subject_expr="current_user",
                            object_expr="resource",
                            operator="call",
                            normalized_relation="delegated_access",
                            evidence=ev,
                        )
                    )

        sec_meta = SecurityMetadata(
            requires_auth=requires_auth,
            auth_dependencies=auth_deps,
            required_roles=required_roles,
            has_owner_check=has_owner_check,
            has_tenant_check=has_tenant_check,
        )

        return sec_meta, predicates


def parse_ast_routes_from_file(file_path: Path | str) -> list[EndpointIR]:
    """Parse route handlers from a single Python source file into EndpointIR."""
    path = Path(file_path)
    if not path.is_file():
        return []

    code = path.read_text(encoding="utf-8")
    tree = ast.parse(code, filename=str(path))
    visitor = FastAPIRouteVisitor(file_path=path)
    visitor.visit(tree)
    return visitor.endpoints


def parse_ast_routes_from_directory(dir_path: Path | str) -> list[EndpointIR]:
    """Recursively parse route handlers from Python files in a directory into EndpointIR."""
    path = Path(dir_path)
    if not path.is_dir():
        return []

    all_endpoints: list[EndpointIR] = []
    for py_file in path.rglob("*.py"):
        all_endpoints.extend(parse_ast_routes_from_file(py_file))

    return all_endpoints
