import jwt

from django.conf import settings
from django.http import JsonResponse


class JWTMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        if request.path == "/":
            return self.get_response(request)

        if request.path == "/auth":
            return self.get_response(request)
        
        authorization = request.headers.get("Authorization")

        if not authorization:
            return JsonResponse(
                {
                    "message": "Authentication required"
                },
                status=401
            )

        try:

            scheme, token = authorization.split(" ", 1)

            if scheme.lower() != "bearer":
                return JsonResponse(
                    {
                        "message": "Invalid authorization scheme"
                    },
                    status=401
                )
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"]
            )

            request.user_payload = payload

        except jwt.ExpiredSignatureError:

            return JsonResponse(
                {
                    "message": "Token has expired"
                },
                status=401
            )

        except jwt.InvalidTokenError:

            return JsonResponse(
                {
                    "message": "Invalid token"
                },
                status=401
            )

        except ValueError:

            return JsonResponse(
                {
                    "message": "Invalid Authorization header"
                },
                status=401
            )

        return self.get_response(request)