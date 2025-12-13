from django.urls import path
from . import views
urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("login/", views.site_login, name="login"),
    path("logout/", views.site_logout, name="logout"),

    path("diagrams/", views.diagram_list, name="diagram_list"),
    path("diagrams/<int:pk>/", views.diagram_editor, name="diagram_editor"),
    path("diagrams/<int:pk>/save/", views.diagram_save, name="diagram_save"),
    path("register/", views.site_register, name="register"),
    path("history/", views.scan_history, name="scan_history"),

]