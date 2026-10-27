from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

from . import dashboard_views as views


urlpatterns = [
    path("login/", LoginView.as_view(template_name="core/dashboard/login.html",
                                     redirect_authenticated_user=True), name="dashboard_login"),
    path("logout/", LogoutView.as_view(next_page="dashboard_login"), name="dashboard_logout"),
    path("", views.home, name="dashboard_home"),
    path("<slug:slug>/", views.overview, name="dashboard_overview"),
    path("<slug:slug>/cases/", views.case_list, name="dashboard_case_list"),
    path("<slug:slug>/cases/<uuid:case_id>/", views.case_detail, name="dashboard_case_detail"),
    path("<slug:slug>/cases/<uuid:case_id>/feedback/", views.submit_case_feedback,
         name="dashboard_feedback_submit"),
    path("<slug:slug>/feedback/<uuid:feedback_id>/review/", views.review_case_feedback,
         name="dashboard_feedback_review"),
    path("<slug:slug>/cases/<uuid:case_id>/restore/", views.restore_case,
         name="dashboard_restore"),
    path("<slug:slug>/settings/", views.dashboard_settings, name="dashboard_settings"),
    path("<slug:slug>/settings/mailboxes/<uuid:mailbox_id>/response/",
         views.update_response_settings, name="dashboard_response_settings"),
]
