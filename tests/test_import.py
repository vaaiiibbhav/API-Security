"""Tests verifying all packages and modules import correctly."""


def test_saga_import():
    """Verify core saga package import and version presence."""
    import saga

    assert hasattr(saga, "__version__")
    assert isinstance(saga.__version__, str)


def test_subpackages_import():
    """Verify all subpackages exist and import cleanly."""
    import saga.core
    import saga.dynamic
    import saga.parser
    import saga.reporting
    import saga.static
    import saga.verifier

    assert saga.core is not None
    assert saga.parser is not None
    assert saga.static is not None
    assert saga.verifier is not None
    assert saga.dynamic is not None
    assert saga.reporting is not None
