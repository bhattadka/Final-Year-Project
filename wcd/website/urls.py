# from django.urls import path
# from . import views

# urlpatterns = [
#     path('', views.analyze_certificate, name='analyze_certificate'),
# ]


# from django.urls import path
# from . import views

# urlpatterns = [
#     path('', views.analyze_certificate, name='analyze_certificate'),  # Default to analysis page
#     path('home/', views.home, name='home'),  # Home page
# ]

from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),  # Home page as the default
    path('analyze/', views.analyze_certificate, name='analyze_certificate'),  # Analysis page
    path('grading-system/', views.grading_system, name='grading_system'),  # Grading system page
]

