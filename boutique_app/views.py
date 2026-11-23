from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate

# REST Framework
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated

# JWT
import uuid
from datetime import datetime, timezone as zona_utc

from django.contrib.auth import login as iniciar_sesion
from django.contrib.auth import logout as cerrar_sesion
from django.db import transaction
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.csrf import ensure_csrf_cookie

from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .decoradores import sesion_requerida

from .autenticacion import AutenticacionSesionJWT
from .models import Prenda, SesionAcceso

@ensure_csrf_cookie
def login(request):
    return render(request, 'boutique_app/login.html')

def catalogo(request):
    return render(request, 'boutique_app/catalogo.html')

@sesion_requerida
def gestion(request):
    return render(request, 'boutique_app/gestion.html')

def detalle(request, id):
    return render(request, 'boutique_app/detalle.html')

@sesion_requerida
def crear(request):
    return render(request, 'boutique_app/crear.html')

@sesion_requerida
def editar(request, id):
    return render(request, 'boutique_app/editar.html')

@sesion_requerida
def eliminar(request, id):
    return render(request, 'boutique_app/eliminar.html')


def crear_refresh(usuario, sesion):
    refresh = RefreshToken.for_user(usuario)
    refresh["sid"] = str(sesion.id)
    return refresh


def expiracion_refresh(refresh):
    return datetime.fromtimestamp(refresh["exp"], tz=zona_utc.utc)

def poner_cookie_refresh(respuesta, refresh):
    respuesta.set_cookie(
        key="refresh_token",
        value=str(refresh),
        max_age=7 * 24 * 60 * 60,
        httponly=True,
        secure=False,  # True cuando publiques con HTTPS
        samesite="Lax",
    )

@method_decorator(csrf_protect, name="dispatch")
class LoginAPI(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response(
                {"error": "Debes ingresar usuario y contraseña."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        usuario = authenticate(username=username, password=password)

        if usuario is None:
            return Response(
                {"error": "Usuario o contraseña incorrectos."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        with transaction.atomic():
            # El valor inicial sólo permite crear la fila; se reemplaza
            # inmediatamente por el jti del Refresh real.
            sesion = SesionAcceso.objects.create(
                usuario=usuario,
                refresh_jti=str(uuid.uuid4()),
                expira=timezone.now() + timezone.timedelta(days=7),
            )

            refresh = crear_refresh(usuario, sesion)
            sesion.refresh_jti = str(refresh["jti"])
            sesion.expira = expiracion_refresh(refresh)
            sesion.save(update_fields=["refresh_jti", "expira"])

        # Crea la sesión Django para las páginas HTML.
        iniciar_sesion(request._request, usuario)
        request._request.session["sid"] = str(sesion.id)

        respuesta = Response(
            {
                "mensaje": "Autenticación correcta.",
                "usuario": usuario.username,
                "access": str(refresh.access_token),
            },
            status=status.HTTP_200_OK,
        )
        poner_cookie_refresh(respuesta, refresh)
        return respuesta


@method_decorator(csrf_protect, name="dispatch")
class RenovarTokenAPI(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        texto_refresh = request.COOKIES.get("refresh_token")

        if not texto_refresh:
            return Response(
                {"error": "Falta el Refresh Token."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            refresh_anterior = RefreshToken(texto_refresh)
            sid = uuid.UUID(str(refresh_anterior["sid"]))
            usuario_id = refresh_anterior["user_id"]
            jti_anterior = str(refresh_anterior["jti"])
        except (TokenError, KeyError, TypeError, ValueError, AttributeError):
            return Response(
                {"error": "Refresh Token inválido o vencido."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        with transaction.atomic():
            sesion = (
                SesionAcceso.objects.select_for_update()
                .select_related("usuario")
                .filter(id=sid, usuario_id=usuario_id)
                .first()
            )

            if (
                sesion is None
                or not sesion.activa
                or sesion.refresh_jti != jti_anterior
            ):
                return Response(
                    {"error": "Sesión vencida, revocada o ya renovada."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Invalida el Refresh anterior.
            refresh_anterior.blacklist()

            refresh_nuevo = crear_refresh(sesion.usuario, sesion)
            sesion.refresh_jti = str(refresh_nuevo["jti"])
            sesion.expira = expiracion_refresh(refresh_nuevo)
            sesion.save(update_fields=["refresh_jti", "expira"])

        respuesta = Response(
            {"access": str(refresh_nuevo.access_token)},
            status=status.HTTP_200_OK,
        )
        poner_cookie_refresh(respuesta, refresh_nuevo)
        return respuesta


class VerSesionAPI(APIView):
    authentication_classes = [AutenticacionSesionJWT]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(
            {
                "usuario": request.user.username,
                "sesion": request.auth["sid"],
            },
            status=status.HTTP_200_OK,
        )


@method_decorator(csrf_protect, name="dispatch")
class LogoutAPI(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        sid = request._request.session.get("sid")
        texto_refresh = request.COOKIES.get("refresh_token")

        if sid and request._request.user.is_authenticated:
            SesionAcceso.objects.filter(
                id=sid,
                usuario=request._request.user,
                revocada__isnull=True,
            ).update(revocada=timezone.now())

        if texto_refresh:
            try:
                RefreshToken(texto_refresh).blacklist()
            except TokenError:
                pass

        cerrar_sesion(request._request)

        respuesta = Response(status=status.HTTP_204_NO_CONTENT)
        respuesta.delete_cookie("refresh_token", samesite="Lax")
        return respuesta


class CatalogoAPI(APIView):
    permission_classes = [AllowAny]

    def get(self, request, id=None):
        if id is not None:
            prenda = get_object_or_404(Prenda, id=id)

            return Response({
                'id': prenda.id,
                'nombre': prenda.nombre,
                'descripcion': prenda.descripcion,
                'categoria': prenda.categoria,
                'color': prenda.color,
                'talla': prenda.talla,
                'precio': prenda.precio,
                'stock': prenda.stock,
                'creado': prenda.creado,
                'actualizado': prenda.actualizado
            }, status=status.HTTP_200_OK)

        prendas = Prenda.objects.all()
        datos = []

        for prenda in prendas:
            datos.append({
                'id': prenda.id,
                'nombre': prenda.nombre,
                'descripcion': prenda.descripcion,
                'categoria': prenda.categoria,
                'color': prenda.color,
                'talla': prenda.talla,
                'precio': prenda.precio,
                'stock': prenda.stock,
                'creado': prenda.creado,
                'actualizado': prenda.actualizado
            })

        return Response(datos, status=status.HTTP_200_OK)

class PrendasAPI(APIView):
    authentication_classes = [AutenticacionSesionJWT]
    permission_classes = [IsAuthenticated]

    def get(self, request, id=None):
            if id is not None:
                prenda = get_object_or_404(Prenda, id=id)
    
                return Response({
                    'id': prenda.id,
                    'nombre': prenda.nombre,
                    'descripcion': prenda.descripcion,
                    'categoria': prenda.categoria,
                    'color': prenda.color,
                    'talla': prenda.talla,
                    'precio': prenda.precio,
                    'stock': prenda.stock,
                    'creado': prenda.creado,
                    'actualizado': prenda.actualizado
                }, status=status.HTTP_200_OK)
    
            prendas = Prenda.objects.all()
            datos = []
    
            for prenda in prendas:
                datos.append({
                    'id': prenda.id,
                    'nombre': prenda.nombre,
                    'descripcion': prenda.descripcion,
                    'categoria': prenda.categoria,
                    'color': prenda.color,
                    'talla': prenda.talla,
                    'precio': prenda.precio,
                    'stock': prenda.stock,
                    'creado': prenda.creado,
                    'actualizado': prenda.actualizado
                })
    
            return Response(datos, status=status.HTTP_200_OK)

    def post(self, request):
        datos = request.data

        campos_obligatorios = [
            'nombre',
            'categoria',
            'color',
            'talla',
            'precio',
            'stock'
        ]

        faltantes = [
            campo for campo in campos_obligatorios
            if datos.get(campo) in [None, '']
        ]

        if faltantes:
            return Response({
                'error': 'Faltan campos obligatorios.',
                'campos': faltantes
            }, status=status.HTTP_400_BAD_REQUEST)

        prenda = Prenda.objects.create(
            nombre=datos.get('nombre'),
            descripcion=datos.get('descripcion'),
            categoria=datos.get('categoria'),
            color=datos.get('color'),
            talla=datos.get('talla'),
            precio=datos.get('precio'),
            stock=datos.get('stock')
        )

        return Response({
            'mensaje': 'Prenda creada correctamente.',
            'prenda': {
                'id': prenda.id,
                'nombre': prenda.nombre,
                'descripcion': prenda.descripcion,
                'categoria': prenda.categoria,
                'color': prenda.color,
                'talla': prenda.talla,
                'precio': prenda.precio,
                'stock': prenda.stock
            }
        }, status=status.HTTP_201_CREATED)

    def put(self, request, id):
        prenda = get_object_or_404(Prenda, id=id)
        datos = request.data

        campos_obligatorios = [
            'nombre',
            'categoria',
            'color',
            'talla',
            'precio',
            'stock'
        ]

        faltantes = [
            campo for campo in campos_obligatorios
            if datos.get(campo) in [None, '']
        ]

        if faltantes:
            return Response({
                'error': 'Faltan campos obligatorios.',
                'campos': faltantes
            }, status=status.HTTP_400_BAD_REQUEST)

        prenda.nombre = datos.get('nombre')
        prenda.descripcion = datos.get('descripcion')
        prenda.categoria = datos.get('categoria')
        prenda.color = datos.get('color')
        prenda.talla = datos.get('talla')
        prenda.precio = datos.get('precio')
        prenda.stock = datos.get('stock')

        prenda.save()

        return Response({
            'mensaje': 'Prenda actualizada correctamente.',
            'prenda': {
                'id': prenda.id,
                'nombre': prenda.nombre,
                'descripcion': prenda.descripcion,
                'categoria': prenda.categoria,
                'color': prenda.color,
                'talla': prenda.talla,
                'precio': prenda.precio,
                'stock': prenda.stock
            }
        }, status=status.HTTP_200_OK)

    def delete(self, request, id):
        prenda = get_object_or_404(Prenda, id=id)
        prenda.delete()

        return Response({
            'mensaje': 'Prenda eliminada correctamente.'
        }, status=status.HTTP_200_OK)