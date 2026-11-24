from functools import wraps
from urllib.parse import urlencode
from uuid import UUID

from django.shortcuts import redirect
from django.urls import reverse

from .models import SesionAcceso


def sesion_requerida(vista):
    @wraps(vista)
    def wrapper(request, *args, **kwargs):
        sid = request.session.get("sid")
        sesion = None

        if request.user.is_authenticated and sid:
            try:
                identificador = UUID(str(sid))
                sesion = SesionAcceso.objects.filter(
                    id=identificador,
                    usuario=request.user,
                ).first()
            except (TypeError, ValueError, AttributeError):
                pass

        if sesion is None or not sesion.activa:
            login_url = reverse("login")
            consulta = urlencode({"next": request.get_full_path()})
            return redirect(f"{login_url}?{consulta}")

        return vista(request, *args, **kwargs)

    return wrapper