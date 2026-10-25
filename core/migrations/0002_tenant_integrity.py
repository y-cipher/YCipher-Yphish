from django.db import migrations


TENANT_SQL = """
CREATE FUNCTION core_enforce_tenant_links() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
        RAISE EXCEPTION 'organization_id is immutable on %', TG_TABLE_NAME;
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME IN ('core_artifact', 'core_analysisrun') THEN
        IF NEW.case_id IS DISTINCT FROM OLD.case_id THEN
            RAISE EXCEPTION 'case_id is immutable on %', TG_TABLE_NAME;
        END IF;
    END IF;

    IF TG_TABLE_NAME = 'core_emailcase' THEN
        IF NOT EXISTS (SELECT 1 FROM core_mailbox WHERE id = NEW.mailbox_id AND organization_id = NEW.organization_id) THEN
            RAISE EXCEPTION 'case mailbox belongs to another organization';
        END IF;
    ELSIF TG_TABLE_NAME = 'core_artifact' THEN
        IF NOT EXISTS (SELECT 1 FROM core_emailcase WHERE id = NEW.case_id AND organization_id = NEW.organization_id) THEN
            RAISE EXCEPTION 'artifact case belongs to another organization';
        END IF;
    ELSIF TG_TABLE_NAME = 'core_analysisrun' THEN
        IF NOT EXISTS (SELECT 1 FROM core_emailcase WHERE id = NEW.case_id AND organization_id = NEW.organization_id) THEN
            RAISE EXCEPTION 'analysis case belongs to another organization';
        END IF;
    ELSIF TG_TABLE_NAME = 'core_evidence' THEN
        IF NOT EXISTS (SELECT 1 FROM core_emailcase WHERE id = NEW.case_id AND organization_id = NEW.organization_id) THEN
            RAISE EXCEPTION 'evidence case belongs to another organization';
        END IF;
        IF NEW.analysis_run_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM core_analysisrun WHERE id = NEW.analysis_run_id
              AND case_id = NEW.case_id AND organization_id = NEW.organization_id
        ) THEN
            RAISE EXCEPTION 'evidence analysis run belongs to another case or organization';
        END IF;
        IF NEW.artifact_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM core_artifact WHERE id = NEW.artifact_id
              AND case_id = NEW.case_id AND organization_id = NEW.organization_id
        ) THEN
            RAISE EXCEPTION 'evidence artifact belongs to another case or organization';
        END IF;
    ELSIF TG_TABLE_NAME = 'core_actionexecution' THEN
        IF NOT EXISTS (SELECT 1 FROM core_emailcase WHERE id = NEW.case_id AND organization_id = NEW.organization_id) THEN
            RAISE EXCEPTION 'action case belongs to another organization';
        END IF;
        IF NEW.analysis_run_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM core_analysisrun WHERE id = NEW.analysis_run_id
              AND case_id = NEW.case_id AND organization_id = NEW.organization_id
        ) THEN
            RAISE EXCEPTION 'action analysis run belongs to another case or organization';
        END IF;
    ELSIF TG_TABLE_NAME = 'core_feedback' THEN
        IF NOT EXISTS (SELECT 1 FROM core_emailcase WHERE id = NEW.case_id AND organization_id = NEW.organization_id) THEN
            RAISE EXCEPTION 'feedback case belongs to another organization';
        END IF;
    ELSIF TG_TABLE_NAME = 'core_auditevent' THEN
        IF NEW.case_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM core_emailcase WHERE id = NEW.case_id AND organization_id = NEW.organization_id
        ) THEN
            RAISE EXCEPTION 'audit case belongs to another organization';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION core_reject_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER core_mailbox_tenant_guard BEFORE UPDATE ON core_mailbox
    FOR EACH ROW EXECUTE FUNCTION core_enforce_tenant_links();
CREATE TRIGGER core_emailcase_tenant_guard BEFORE INSERT OR UPDATE ON core_emailcase
    FOR EACH ROW EXECUTE FUNCTION core_enforce_tenant_links();
CREATE TRIGGER core_artifact_tenant_guard BEFORE INSERT OR UPDATE ON core_artifact
    FOR EACH ROW EXECUTE FUNCTION core_enforce_tenant_links();
CREATE TRIGGER core_analysisrun_tenant_guard BEFORE INSERT OR UPDATE ON core_analysisrun
    FOR EACH ROW EXECUTE FUNCTION core_enforce_tenant_links();
CREATE TRIGGER core_evidence_tenant_guard BEFORE INSERT OR UPDATE ON core_evidence
    FOR EACH ROW EXECUTE FUNCTION core_enforce_tenant_links();
CREATE TRIGGER core_actionexecution_tenant_guard BEFORE INSERT OR UPDATE ON core_actionexecution
    FOR EACH ROW EXECUTE FUNCTION core_enforce_tenant_links();
CREATE TRIGGER core_feedback_tenant_guard BEFORE INSERT OR UPDATE ON core_feedback
    FOR EACH ROW EXECUTE FUNCTION core_enforce_tenant_links();
CREATE TRIGGER core_auditevent_tenant_guard BEFORE INSERT ON core_auditevent
    FOR EACH ROW EXECUTE FUNCTION core_enforce_tenant_links();
CREATE TRIGGER core_auditevent_immutable BEFORE UPDATE OR DELETE ON core_auditevent
    FOR EACH ROW EXECUTE FUNCTION core_reject_audit_mutation();
"""

REVERSE_SQL = """
DROP TRIGGER IF EXISTS core_auditevent_immutable ON core_auditevent;
DROP TRIGGER IF EXISTS core_auditevent_tenant_guard ON core_auditevent;
DROP TRIGGER IF EXISTS core_feedback_tenant_guard ON core_feedback;
DROP TRIGGER IF EXISTS core_actionexecution_tenant_guard ON core_actionexecution;
DROP TRIGGER IF EXISTS core_evidence_tenant_guard ON core_evidence;
DROP TRIGGER IF EXISTS core_analysisrun_tenant_guard ON core_analysisrun;
DROP TRIGGER IF EXISTS core_artifact_tenant_guard ON core_artifact;
DROP TRIGGER IF EXISTS core_emailcase_tenant_guard ON core_emailcase;
DROP TRIGGER IF EXISTS core_mailbox_tenant_guard ON core_mailbox;
DROP FUNCTION IF EXISTS core_reject_audit_mutation();
DROP FUNCTION IF EXISTS core_enforce_tenant_links();
"""


class Migration(migrations.Migration):
    dependencies = [("core", "0001_initial")]
    operations = [migrations.RunSQL(TENANT_SQL, REVERSE_SQL)]
