from django.shortcuts import render
from django.views import View
from django.http import HttpResponse


class EncryptionView(View):
    def get(self, request):
        return render(request, "core/encryption.html")


class DecryptionView(View):
    def get(self, request):
        return render(request, "core/decryption.html")


class IndexView(View):
    def get(self, request):
        return render(request, "core/index.html")


class EncryptionHelpView(View):
    def get(self, request):
        return render(request, "core/help_encryption.html")


class DecryptionHelpView(View):
    def get(self, request):
        return render(request, "core/help_decryption.html")


class HashingView(View):
    def get(self, request):
        return render(request, "core/hashing.html")
