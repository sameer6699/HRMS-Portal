from django.shortcuts import redirect
from django.urls import reverse

class AuthMiddleware:
    """
    Middleware to restrict access to authenticated users only,
    unless accessing login/register/logout/static/admin URLs.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        allowed_paths = [
            reverse("helpdesk_portal")
        ]

        if (request.path in allowed_paths):
          if not request.session.get("user_id"):
              print(f"[AuthMiddleware] Unauthorized access to {request.path}. Redirecting to login.")
              return redirect("user_login")

        response = self.get_response(request)
        return response