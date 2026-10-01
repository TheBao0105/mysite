import hashlib
import json
from datetime import datetime, timedelta, timezone

import jwt
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import User


SECRET_KEY = settings.SECRET_KEY

@csrf_exempt
def login(request):

    if request.method != "POST":
        return JsonResponse(
            {"message": "Only POST method is allowed"},
            status=405
        )

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse(
            {"message": "Invalid JSON"},
            status=400
        )

    username = data.get("userName")
    password = data.get("password")

    if not username or not password:
        return JsonResponse(
            {"message": "userName and password are required"},
            status=400
        )

    password_md5 = hashlib.md5(
        password.encode("utf-8")
    ).hexdigest()

    try:
        user = User.objects.get(username=username)

    except User.DoesNotExist:
        return JsonResponse(
            {"message": "Invalid username or password"},
            status=401
        )


    if user.password != password and user.password != password_md5:
        return JsonResponse(
            {"message": "Invalid username or password"},
            status=401
        )

    payload = {
        "id_user": user.id_user,
        "username": user.username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256"
    )

    user.token = token
    user.save()

    return JsonResponse({
        "message": "Login successful",
        "token": token
    })

@csrf_exempt
def auth(request):

    if request.method != "GET":
        return JsonResponse(
            {"message": "Only GET method is allowed"},
            status=405
        )

    authorization = request.headers.get("Authorization")

    if not authorization:
        return JsonResponse(
            {"message": "Authorization header is required"},
            status=401
        )

    try:

        scheme, token = authorization.split(" ", 1)

        if scheme.lower() != "bearer":
            return JsonResponse(
                {"message": "Invalid authorization scheme"},
                status=401
            )

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        return JsonResponse({
            "message": "Token is valid",
            "user": payload["username"]
        })

    except ValueError:
        return JsonResponse(
            {"message": "Invalid Authorization header"},
            status=401
        )

    except jwt.ExpiredSignatureError:
        return JsonResponse(
            {"message": "Token has expired"},
            status=401
        )

    except jwt.InvalidTokenError:
        return JsonResponse(
            {"message": "Invalid token"},
            status=401
        )


# =========================================================
# 3. HELLO WORLD
# GET /hello/
# =========================================================

@csrf_exempt
def hello(request):

    if request.method != "GET":
        return JsonResponse(
            {"message": "Only GET method is allowed"},
            status=405
        )

    return JsonResponse({
        "message": "Hello World"
    })