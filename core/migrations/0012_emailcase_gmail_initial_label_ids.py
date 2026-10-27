from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0011_response_control_tenant_guard")]

    operations = [
        migrations.AddField(
            model_name="emailcase",
            name="gmail_initial_label_ids",
            field=models.JSONField(blank=True, null=True),
        ),
    ]
