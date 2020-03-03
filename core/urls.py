from django.urls import path
from .views import EncryptionView, DecryptionView, EncryptionHelpView, DecryptionHelpView, HashingView

app_name = 'crypto'
urlpatterns = [
    path('encrypt/', EncryptionView.as_view(), name="encrypt"),
    path('decrypt/', DecryptionView.as_view(), name="decrypt"),
    path('encrypt/help/', EncryptionHelpView.as_view(), name="encrypt_help"),
    path('decrypt/help/', DecryptionHelpView.as_view(), name="decrypt_help"),
    path('hashing/', HashingView.as_view(), name="hashing"),
]
