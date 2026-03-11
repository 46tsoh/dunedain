"""Shared pytest fixtures for the test suite."""
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True)
def mock_celery_delay():
    """Prevent tests from connecting to Redis by mocking run_scan.delay.

    The CI environment has no Redis broker, so any call to run_scan.delay()
    would raise a kombu.exceptions.OperationalError.  This autouse fixture
    replaces the delay method with a no-op MagicMock for every test.
    """
    with patch("app.tasks.scan.run_scan.delay", return_value=MagicMock()) as m:
        yield m
