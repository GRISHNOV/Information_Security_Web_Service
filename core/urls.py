from django.urls import path
from .views import  EncryptionView, DecryptionView, EncryptionHelpView, DecryptionHelpView, HashingView,\
                    AESEncryptionView, AESDecryptionView

app_name = 'crypto'
urlpatterns = [
    path('encrypt/help/', EncryptionHelpView.as_view(), name="encrypt_help"),
    path('decrypt/help/', DecryptionHelpView.as_view(), name="decrypt_help"),
    path('hashing/', HashingView.as_view(), name="hashing"),

    path('basic/encrypt/', EncryptionView.as_view(), name="basic_encrypt"),
    path('basic/decrypt/', DecryptionView.as_view(), name="basic_decrypt"),

    path('aes/encrypt/', AESEncryptionView.as_view(), name="aes_encrypt"),
    path('aes/decrypt/', AESDecryptionView.as_view(), name="aes_decrypt"),
]
