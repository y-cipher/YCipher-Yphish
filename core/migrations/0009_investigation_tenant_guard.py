from django.db import migrations


FORWARD = """
CREATE FUNCTION core_enforce_investigation_links() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.organization_id IS DISTINCT FROM OLD.organization_id OR
        NEW.mailbox_id IS DISTINCT FROM OLD.mailbox_id OR
        NEW.case_id IS DISTINCT FROM OLD.case_id OR
        NEW.analysis_run_id IS DISTINCT FROM OLD.analysis_run_id
    ) THEN
        RAISE EXCEPTION 'investigation relationships are immutable';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM core_emailcase c
        JOIN core_mailbox m ON m.id = c.mailbox_id
        JOIN core_analysisrun a ON a.case_id = c.id
        WHERE c.id = NEW.case_id AND c.organization_id = NEW.organization_id
          AND m.id = NEW.mailbox_id AND m.organization_id = NEW.organization_id
          AND a.id = NEW.analysis_run_id AND a.organization_id = NEW.organization_id
    ) THEN
        RAISE EXCEPTION 'investigation case, mailbox, analysis run, and organization must match';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER core_investigation_tenant_guard
BEFORE INSERT OR UPDATE ON core_investigationrun
FOR EACH ROW EXECUTE FUNCTION core_enforce_investigation_links();
"""

REVERSE = """
DROP TRIGGER IF EXISTS core_investigation_tenant_guard ON core_investigationrun;
DROP FUNCTION IF EXISTS core_enforce_investigation_links();
"""


class Migration(migrations.Migration):
    dependencies = [("core", "0008_mailbox_investigation_conversation_enabled_and_more")]
    operations = [migrations.RunSQL(FORWARD, REVERSE)]
