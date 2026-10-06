"""AST extraction engine for principals, object references, and auth predicates."""

import ast
from pathlib import Path

from saga.ir.evidence import Evidence
from saga.ir.models import PredicateType
from saga.static.models import (
    ASTAnalysisResult,
    ExtractedAuthPredicate,
    ExtractedObjectRef,
    ExtractedPrincipal,
)


class SecurityASTVisitor(ast.NodeVisitor):
    """AST Visitor extracting security context: principals, objects, and auth predicates."""

    def __init__(self, file_path: Path | str | None = None) -> None:
        self.file_path = Path(file_path) if file_path else None
        self.results: list[ASTAnalysisResult] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Process synchronous function definitions."""
        self._analyze_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Process asynchronous function definitions."""
        self._analyze_function(node)
        self.generic_visit(node)

    def _analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        http_method = "GET"
        path = "/"
        has_decorator = False
        for d in node.decorator_list:
            if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute):
                if d.func.attr.lower() in ("get", "post", "put", "patch", "delete"):
                    has_decorator = True
                    http_method = d.func.attr.upper()
                    if d.args and isinstance(d.args[0], ast.Constant):
                        path = str(d.args[0].value)

        principals = self._extract_principals(node)
        objects = self._extract_objects(node)
        predicates = self._extract_predicates(node)

        # Include if function has route decorator or extracted security features
        if has_decorator or principals or objects or predicates:
            res = ASTAnalysisResult(
                http_method=http_method,
                path=path,
                handler_name=node.name,
                source_file=self.file_path,
                source_line=node.lineno,
                principals=principals,
                objects=objects,
                predicates=predicates,
            )
            self.results.append(res)


    def _extract_principals(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[ExtractedPrincipal]:
        principals: list[ExtractedPrincipal] = []
        defaults_offset = len(node.args.args) - len(node.args.defaults)

        for idx, arg in enumerate(node.args.args):
            param_name = arg.arg
            if param_name in ("self", "cls"):
                continue

            type_annotation = None
            if arg.annotation:
                if isinstance(arg.annotation, ast.Name):
                    type_annotation = arg.annotation.id
                elif isinstance(arg.annotation, ast.Constant):
                    type_annotation = str(arg.annotation.value)

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

            # Exclude database session dependencies (e.g. db: Session = Depends(get_db))
            is_db_dep = param_name in ("db", "session") or (
                dependency_func is not None and "db" in dependency_func.lower()
            )

            # Matching principal pattern: Depends(...) or param named current_user / user
            is_principal_name = (
                "user" in param_name.lower() or "principal" in param_name.lower()
            ) and not param_name.endswith("_id") and not param_name.endswith("_uuid")

            if not is_db_dep and (is_dep or is_principal_name):
                confidence = 1.0 if is_dep else 0.85
                ev = Evidence(
                    source_file=self.file_path,
                    source_line=node.lineno,
                    ast_node_type="arg",
                    expression_snippet=f"{param_name}: {type_annotation}",
                    confidence_score=confidence,
                )
                principals.append(
                    ExtractedPrincipal(
                        param_name=param_name,
                        type_annotation=type_annotation,
                        dependency_func=dependency_func,
                        evidence=ev,
                    )
                )

        return principals

    def _extract_objects(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[ExtractedObjectRef]:
        objects: list[ExtractedObjectRef] = []

        for body_node in ast.walk(node):
            if not isinstance(body_node, ast.Call):
                continue

            func = body_node.func
            lineno = getattr(body_node, "lineno", node.lineno)

            # Pattern 1: db.query(Document) or session.query(Order)
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "query"
                and body_node.args
                and isinstance(body_node.args[0], ast.Name)
            ):
                entity_name = body_node.args[0].id
                ev = Evidence(
                    source_file=self.file_path,
                    source_line=lineno,
                    ast_node_type="Call",
                    expression_snippet=f"db.query({entity_name})",
                    confidence_score=1.0,
                )
                objects.append(
                    ExtractedObjectRef(
                        entity_name=entity_name,
                        access_method="query",
                        evidence=ev,
                    )
                )

            # Pattern 2: Order.get(...) or Document.get(...)
            elif (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and isinstance(func.value, ast.Name)
                and func.value.id not in ("router", "app")
            ):
                entity_name = func.value.id
                ev = Evidence(
                    source_file=self.file_path,
                    source_line=lineno,
                    ast_node_type="Call",
                    expression_snippet=f"{entity_name}.get(...)",
                    confidence_score=1.0,
                )
                objects.append(
                    ExtractedObjectRef(
                        entity_name=entity_name,
                        access_method="get",
                        evidence=ev,
                    )
                )

            # Pattern 3: .filter(...) or .filter_by(...)
            elif isinstance(func, ast.Attribute) and func.attr in ("filter", "filter_by"):
                filter_param = None
                for arg in body_node.args:
                    if isinstance(arg, ast.Compare) and isinstance(arg.left, ast.Attribute):
                        for comp in arg.comparators:
                            if isinstance(comp, ast.Name):
                                filter_param = comp.id
                ev = Evidence(
                    source_file=self.file_path,
                    source_line=lineno,
                    ast_node_type="Call",
                    expression_snippet=func.attr,
                    confidence_score=0.9,
                )
                objects.append(
                    ExtractedObjectRef(
                        entity_name="ORM_Filter",
                        access_method=func.attr,
                        filter_param=filter_param,
                        evidence=ev,
                    )
                )

        return objects

    def _extract_predicates(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[ExtractedAuthPredicate]:
        predicates: list[ExtractedAuthPredicate] = []

        # Check for delegated helper policy calls (e.g. check_custom_policy, can_access)
        for body_node in ast.walk(node):
            if isinstance(body_node, ast.Call):
                func_name = ""
                if isinstance(body_node.func, ast.Name):
                    func_name = body_node.func.id
                elif isinstance(body_node.func, ast.Attribute):
                    func_name = body_node.func.attr

                if any(
                    kw in func_name.lower()
                    for kw in ("policy", "authorize", "can_access", "check_custom")
                ):
                    ev = Evidence(
                        source_file=self.file_path,
                        source_line=getattr(body_node, "lineno", node.lineno),
                        ast_node_type="Call",
                        expression_snippet=ast.unparse(body_node)
                        if hasattr(ast, "unparse")
                        else func_name,
                        confidence_score=0.9,
                    )
                    predicates.append(
                        ExtractedAuthPredicate(
                            predicate_type=PredicateType.DELEGATED,
                            subject_expr="current_user",
                            object_expr="resource",
                            operator="call",
                            evidence=ev,
                        )
                    )

            if isinstance(body_node, ast.Compare):
                left_expr = ast.unparse(body_node.left) if hasattr(ast, "unparse") else ""
                comp_exprs = [
                    ast.unparse(c) for c in body_node.comparators if hasattr(ast, "unparse")
                ]

                if not comp_exprs:
                    continue

                right_expr = comp_exprs[0]
                op_str = "=="
                if body_node.ops:
                    op_type = type(body_node.ops[0])
                    if op_type is ast.Eq:
                        op_str = "=="
                    elif op_type is ast.NotEq:
                        op_str = "!="

                all_str = f"{left_expr} {op_str} {right_expr}"

                has_user_context = any(
                    ctx in left_expr or ctx in right_expr
                    for ctx in ("current_user", "principal", "user_context", "tenant_id")
                )
                if not has_user_context:
                    continue

                predicate_type = None
                if "owner_id" in all_str or "user_id" in all_str or "owner" in all_str:
                    predicate_type = PredicateType.OWNERSHIP
                elif "tenant_id" in all_str or "tenant" in all_str:
                    predicate_type = PredicateType.TENANT
                elif "role" in all_str:
                    predicate_type = PredicateType.ROLE

                if predicate_type:
                    if "current_user" in left_expr:
                        subject = left_expr
                        obj = right_expr
                    else:
                        subject = right_expr
                        obj = left_expr

                    ev = Evidence(
                        source_file=self.file_path,
                        source_line=body_node.lineno,
                        ast_node_type="Compare",
                        expression_snippet=all_str,
                        confidence_score=1.0,
                    )

                    predicates.append(
                        ExtractedAuthPredicate(
                            predicate_type=predicate_type,
                            subject_expr=subject,
                            object_expr=obj,
                            operator=op_str,
                            evidence=ev,
                        )
                    )

        return predicates



def extract_ast_security_from_file(file_path: Path | str) -> list[ASTAnalysisResult]:
    """Extract principal, object, and predicate security context from a Python file.

    Args:
        file_path: Path to Python source file.

    Returns:
        List of ASTAnalysisResult for handlers defined in the file.
    """
    path = Path(file_path)
    if not path.is_file():
        return []

    code = path.read_text(encoding="utf-8")
    tree = ast.parse(code, filename=str(path))
    visitor = SecurityASTVisitor(file_path=path)
    visitor.visit(tree)
    return visitor.results


def extract_ast_security_from_directory(dir_path: Path | str) -> list[ASTAnalysisResult]:
    """Recursively extract security context from Python files in a directory.

    Args:
        dir_path: Path to directory containing Python source files.

    Returns:
        List of ASTAnalysisResult for handlers discovered in the directory.
    """
    path = Path(dir_path)
    if not path.is_dir():
        return []

    results: list[ASTAnalysisResult] = []
    for py_file in path.rglob("*.py"):
        results.extend(extract_ast_security_from_file(py_file))

    return results
