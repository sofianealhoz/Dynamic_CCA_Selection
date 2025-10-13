from django.shortcuts import render
from django.http import JsonResponse

# Create your views here.
def resultats_list(request):
    resultats = [1,3,5]
    return JsonResponse({"resultats": resultats})