import uuid

from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import SesionAcceso


class AutenticacionSesionJWT(JWTAuthentication):
    def authenticate(self, request):
        resultado = super().authenticate(request)

        if resultado is None:
            return None

        usuario, token = resultado
        sid = token.get("sid")

        try:
            sid = uuid.UUID(str(sid))
        except (TypeError, ValueError, AttributeError):
            raise AuthenticationFailed("El token no contiene una sesión válida.")

        sesion = SesionAcceso.objects.filter(
            id=sid,
            usuario=usuario,
        ).first()

        if sesion is None or not sesion.activa:
            raise AuthenticationFailed("La sesión venció o fue revocada.")

        return usuario, token