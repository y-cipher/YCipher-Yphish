from django.db import migrations


FORWARD = """
CREATE FUNCTION core_enforce_response_control_links() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.organization_id IS DISTINCT FROM OLD.organization_id OR
        NEW.mailbox_id IS DISTINCT FROM OLD.mailbox_id
    ) THEN
        RAISE EXCEPTION 'response control relationships are immutable';
    END IF;
    IF NEW.mailbox_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM core_mailbox
        WHERE id = NEW.mailbox_id AND organization_id = NEW.organization_id
    ) THEN
        RAISE EXCEPTION 'response control mailbox belongs to another organization';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER core_response_control_tenant_guard
BEFORE INSERT OR UPDATE ON core_responsecontrol
FOR EACH ROW EXECUTE FUNCTION core_enforce_response_control_links();
"""

REVERSE = """
DROP TRIGGER IF EXISTS core_response_control_tenant_guard ON core_responsecontrol;
DROP FUNCTION IF EXISTS core_enforce_response_control_links();
"""


class Migration(migrations.Migration):
    dependencies = [("core", "0010_responsecontrol_actionexecution_last_dispatched_at_and_more")]
    operations = [migrations.RunSQL(FORWARD, REVERSE)]
