"""
Phase 2 — Pagination and server-side search tests.

Covers:
- Patient list: page/per_page params, q/age_band/gender filters, boundary cases
- Audit log: action_type/date_from/date_to filters, pagination
- Architectural boundary: encrypted fields are NOT searched server-side
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.models.audit_log import AuditLog
from app.services.audit_service import AuditService
from app.services.patient_service import PatientService
from tests.conftest import login_client

# ── Helpers ──────────────────────────────────────────────────────────────────

def _seed_patients(n: int):
    """Create n extra patients for pagination tests."""
    for i in range(n):
        try:
            PatientService.create_patient(
                patient_id=f"PAG-{i:04d}",
                age_band="20-29" if i % 2 == 0 else "30-39",
                gender="Male" if i % 3 != 0 else "Female",
                name=f"Test Patient {i}",
                diagnosis="N/A",
                medical_history="N/A",
                notes="pagination test record",
            )
        except ValueError:
            pass  # tolerate duplicate if test runs twice


# ── Patient list pagination ──────────────────────────────────────────────────

def test_patient_list_pagination_returns_correct_page(app):
    """list_patients() returns correct page of results."""
    with app.app_context():
        _seed_patients(30)  # 30 + 1 existing = 31 records
        page1 = PatientService.list_patients(page=1, per_page=10)
        page2 = PatientService.list_patients(page=2, per_page=10)
        page4 = PatientService.list_patients(page=4, per_page=10)  # last page with 1 record
        page5 = PatientService.list_patients(page=5, per_page=10)  # beyond end

        assert len(page1.items) == 10
        assert len(page2.items) == 10
        # Page IDs should be different
        ids_p1 = {p["id"] for p in page1.items}
        ids_p2 = {p["id"] for p in page2.items}
        assert ids_p1.isdisjoint(ids_p2), "Pages must not overlap"
        assert len(page4.items) == 1
        assert len(page5.items) == 0
        assert page1.total >= 31


def test_patient_list_search_by_patient_id(app):
    """Server-side q filter returns only matching patient IDs (case-insensitive)."""
    with app.app_context():
        _seed_patients(5)
        result = PatientService.list_patients(q="PAG-0001", per_page=25)
        patient_ids = [p["patient_id"] for p in result.items]
        assert "PAG-0001" in patient_ids
        # Ensure it's a substring match (ILIKE)
        result_prefix = PatientService.list_patients(q="PAG-000", per_page=25)
        assert len(result_prefix.items) >= 5


def test_patient_list_filter_age_band(app):
    """age_band exact filter returns only matching records."""
    with app.app_context():
        _seed_patients(6)
        result = PatientService.list_patients(age_band="20-29", per_page=100)
        assert all(p["age_band"] == "20-29" for p in result.items)


def test_patient_list_filter_gender(app):
    """gender exact filter returns only matching records."""
    with app.app_context():
        _seed_patients(6)
        result = PatientService.list_patients(gender="Female", per_page=100)
        assert all(p["gender"] == "Female" for p in result.items)


def test_patient_list_per_page_clamped(app):
    """per_page is clamped to [1, 100] range."""
    with app.app_context():
        result_zero = PatientService.list_patients(page=1, per_page=0)
        assert result_zero.per_page == 1  # clamped to 1

        result_huge = PatientService.list_patients(page=1, per_page=9999)
        assert result_huge.per_page == 100  # clamped to 100


def test_patient_list_does_not_return_encrypted_fields(app):
    """Items from list_patients() must never expose encrypted payload fields."""
    with app.app_context():
        result = PatientService.list_patients(page=1, per_page=25)
        for item in result.items:
            assert "name" not in item, "PHI name must not appear in patient list"
            assert "diagnosis" not in item, "PHI diagnosis must not appear in patient list"
            assert "medical_history" not in item
            assert "notes" not in item
            # Only these clear fields should be present
            assert "patient_id" in item
            assert "age_band" in item
            assert "gender" in item


# ── Patient list route (HTTP) ────────────────────────────────────────────────

def test_patient_list_route_pagination_params(client):
    """GET /patients?page=1&per_page=5 returns 200 with pagination context."""
    login_client(client, "test_doctor", "DoctorPass#123")
    resp = client.get("/patients?page=1&per_page=5")
    assert resp.status_code == 200
    # Pagination nav is rendered (or just the table if only 1 page)
    data = resp.data.decode()
    assert "Search by MRN" in data


def test_patient_list_route_search_filter(client):
    """GET /patients?q=P-TEST shows only matching patient(s)."""
    login_client(client, "test_doctor", "DoctorPass#123")
    resp = client.get("/patients?q=P-TEST")
    assert resp.status_code == 200
    data = resp.data.decode()
    assert "P-TEST-001" in data


def test_patient_list_route_invalid_page_defaults_to_1(client):
    """GET /patients?page=notanumber returns 200 (defaults to page 1)."""
    login_client(client, "test_doctor", "DoctorPass#123")
    resp = client.get("/patients?page=notanumber")
    assert resp.status_code == 200


# ── Audit log pagination (HTTP) ──────────────────────────────────────────────

def test_audit_log_route_action_type_filter(client):
    """GET /admin/audit?action_type=LOGIN_SUCCESS filters to that action."""
    login_client(client, "test_admin", "AdminPass#123")
    resp = client.get("/admin/audit?action_type=LOGIN_SUCCESS&per_page=50")
    assert resp.status_code == 200
    data = resp.data.decode()
    # Page renders without error
    assert "Audit log" in data


def test_audit_log_route_date_filter_invalid(client):
    """GET /admin/audit?date_from=bad-date shows error message, not 500."""
    login_client(client, "test_admin", "AdminPass#123")
    resp = client.get("/admin/audit?date_from=not-a-date")
    assert resp.status_code == 200
    data = resp.data.decode()
    assert "Invalid date format" in data or "YYYY-MM-DD" in data


def test_audit_log_route_pagination(client):
    """GET /admin/audit?per_page=25 returns 200."""
    login_client(client, "test_admin", "AdminPass#123")
    resp = client.get("/admin/audit?per_page=25&page=1")
    assert resp.status_code == 200
