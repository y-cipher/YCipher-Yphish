# Deploy Yphish on Render

This guide deploys the dashboard and background services from the Yphish repository using Render Blueprints. It keeps Gmail access separate and disabled until a Workspace administrator authorizes it.

## What this deployment creates

`render.yaml` defines a Render PostgreSQL database, a private RabbitMQ service, a Django web service, a Celery worker, and a single Celery Beat scheduler. The web, worker, and scheduler use one private S3-compatible bucket for MIME artifacts so that files are durable and accessible from the separate processes. The Blueprint uses paid service plans and a disk-backed RabbitMQ service.

Render persistent disks are private to the service they are attached to, so Yphish does not try to share a filesystem disk between web and worker. [Render documents this disk boundary](https://render.com/docs/disks). Free Render services are unsuitable for this deployment: free web services have no persistent disk, free PostgreSQL expires after 30 days, and background processing and persistent storage require paid resources. See [Render's free-plan limits](https://render.com/docs/free). Review the cost estimate shown by Render before provisioning.

The external MinIO/S3 service is not created by the Blueprint because its administrator must create the private bucket and a bucket-limited access key first. Render's [MinIO deployment guide](https://render.com/docs/deploy-minio) is one option. A managed S3-compatible provider also works.

## Before you deploy

1. Commit and push the Render configuration to the GitHub branch you intend to deploy. Do not commit `.env`, service-account JSON, object-storage keys, database backups, or real Gmail content.
2. Create a private S3-compatible bucket named `yphish-private-artifacts`. Keep public access disabled. Create an application identity limited to this bucket with the operations needed to list, read, write, and delete objects. Keep account administrator credentials separate from Yphish.
3. If using MinIO on Render, deploy it in the same Render region as Yphish and configure its storage disk. Use the HTTPS S3 API endpoint shown by that service. The bucket should remain private.
4. Confirm the Render region in `render.yaml` matches the object-storage service. PostgreSQL and RabbitMQ are provisioned in Singapore by default; change all `region` values together if needed.

## Create the Render services

1. In the Render Dashboard, choose **New → Blueprint** and connect the Yphish GitHub repository and deployment branch. Render reads `render.yaml` and shows the resources and plans before creation.
2. When prompted for `PRIVATE_ARTIFACT_S3_ENDPOINT`, enter the S3 API endpoint, including `https://` and any required port. Enter the bucket-scoped access key and secret for `PRIVATE_ARTIFACT_S3_ACCESS_KEY` and `PRIVATE_ARTIFACT_S3_SECRET_KEY`. These values are requested separately for web, worker, and Beat because every process that imports Django settings needs the storage configuration. Never paste a MinIO root password or cloud account key here.
3. Review the plan and approve resource creation. The Blueprint creates PostgreSQL, private RabbitMQ with persistent disk, the web service, a worker, and exactly one Beat scheduler. Render does not expose the RabbitMQ private service to the public internet.
4. Wait for the web deploy to finish. Its paid pre-deploy command runs `python manage.py migrate --noinput`; the start command collects static files and launches Gunicorn on Render's assigned port. Open the web service logs and confirm it reports a successful deploy.
5. Open `https://yphish-web.onrender.com/health/`. It should return `{"status":"ok"}`. If you add a custom domain, update `DJANGO_ALLOWED_HOSTS` and `DJANGO_CSRF_TRUSTED_ORIGINS` in the shared `yphish-render-runtime` environment group to match it, then redeploy.

If the S3 values were not available during Blueprint creation, add them to the Environment page of **all three** Yphish processes (`yphish-web`, `yphish-worker`, and `yphish-beat`) before starting them. The app fails closed when S3 storage is selected without a bucket, endpoint, access key, and secret key.

## Create a local demonstration login

The deployed instance starts with an empty database and no default account. From the Render Shell for `yphish-web`, create synthetic demonstration cases and set a password:

```sh
DJANGO_DEBUG=1 python manage.py bootstrap_dev --with-demo-emails
python manage.py changepassword demo_owner
```

`DJANGO_DEBUG=1` applies only to that one command in the Shell; the running web service remains configured with `DJANGO_DEBUG=0`. The demonstration records use reserved `example.test` addresses, have no real message body or MIME, and cannot connect to Gmail. Sign in at `https://yphish-web.onrender.com/dashboard/` as `demo_owner` with the password you set.

## Check background services

Use the Render Shell on `yphish-worker` for operational commands:

```sh
python manage.py check
python manage.py gmail_health --json
celery -A config inspect ping
```

The health endpoint checks only the web process. `gmail_health` should report a connected broker, a responding worker, and a scheduler heartbeat after Beat has dispatched work. No enrolled mailbox is expected in a demo-only deployment.

## Gmail authorization status

This Render configuration sets `GMAIL_RESPONSE_ENABLED=0`. It does not provide Google credentials or connect any mailbox. Personal `@gmail.com` OAuth enrollment is not implemented. A live Workspace connection requires a Workspace administrator to approve domain-wide delegation and named mailbox enrollment; Yphish's application allowlist does not reduce the provider-level identities that a DWD credential may impersonate.

If a Workspace administrator later authorizes ingestion, add the ingestion service-account JSON as a Render secret file to **web and worker only**, with filename `google-ingestion-service-account.json`. Set `GOOGLE_INGESTION_SERVICE_ACCOUNT_FILE=/etc/secrets/google-ingestion-service-account.json` on those two services. The Docker image adds its app user to Render's documented secret-file group. Keep automatic response disabled until a separate response identity, live checks, and operator approval are complete. If response is later authorized, add its JSON secret only to the worker and follow [Gmail setup](gmail.md) and [trial operations](module11-trial-operations.md).

## Important operating limits

- Keep one Beat service. Multiple schedulers can dispatch duplicate periodic work.
- Keep the response switch off until real Workspace authorization, action recovery, and suspension have been verified.
- The classifier artifact and indicator snapshots are not bundled in this deployment. Until explicitly installed and verified, classifier availability and indicator coverage remain limited.
- The Render profile leaves artifact retention disabled. Approve and configure a retention period before storing real Gmail content.
- Configure database and object-storage backups and perform a restore drill. Render's managed database recovery and MinIO disk snapshots are not a substitute for a jointly tested database-plus-object restore.
- This setup has not been live-verified against a Render account or Gmail. Successful deployment and health checks do not establish Workspace authorization, Gmail behavior, detection accuracy, or backup recovery.

## Official Render references

- [Deploy a Django app](https://render.com/docs/deploy-django)
- [Blueprint specification](https://render.com/docs/blueprint-spec)
- [Docker services](https://render.com/docs/docker)
- [Background workers](https://render.com/docs/background-workers)
- [RabbitMQ on Render](https://render.com/docs/deploy-rabbitmq)
- [Environment variables and secret files](https://render.com/docs/configure-environment-variables)
- [Persistent disks](https://render.com/docs/disks)
