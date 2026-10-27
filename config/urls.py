from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path


def health(_request):
    return JsonResponse({"status": "ok"})


urlpatterns = [
    path("health/", health, name="health"),
    path("dashboard/", include("core.dashboard_urls")),
    path("admin/", admin.site.urls),
]
