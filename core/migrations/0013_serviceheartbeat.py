import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0012_emailcase_gmail_initial_label_ids")]

    operations = [
        migrations.CreateModel(
            name="ServiceHeartbeat",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("name", models.CharField(max_length=40, unique=True)),
                ("last_seen_at", models.DateTimeField()),
            ],
        ),
    ]
