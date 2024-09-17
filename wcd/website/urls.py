from django.urls import path
from . import views

urlpatterns = [
    path('', views.analyze_certificate, name='analyze_certificate'),
]
