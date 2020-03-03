from django.contrib import admin
from django.urls import path, include
from core.views import IndexView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('crypto/', include('core.urls', namespace="crypto")),
    path('',  IndexView.as_view()),
]
