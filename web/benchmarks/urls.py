from django.urls import path
from . import views

urlpatterns = [
    path("runs/", views.results, name="runs"),             # GET
    path("runs/launch/", views.launch_benchmark, name="launch"),  # POST
    path("runs/<int:pk>/", views.run_detail, name="detail"),      # GET détail
]