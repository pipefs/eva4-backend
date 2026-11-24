from django.urls import path
from . import views

from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("", views.catalogo, name="catalogo"),
    path("login/", views.login, name="login"),
    path("gestion/", views.gestion, name="gestion"),
    path("detalle/<int:id>/", views.detalle, name="detalle"),
    path("crear/", views.crear, name="crear"),
    path("editar/<int:id>/", views.editar, name="editar"),
    path("eliminar/<int:id>/", views.eliminar, name="eliminar"),

    # API Autenticacion
    path("api/login/", views.LoginAPI.as_view(), name='api_login'),
    path("api/token/refresh/", views.RenovarTokenAPI.as_view(), name="api_token_refresh"),
    path("api/sesion/", views.VerSesionAPI.as_view(), name="api_sesion"),
    path("api/logout/", views.LogoutAPI.as_view(), name="api_logout"),

    # API GET
    path("api/catalogo/", views.CatalogoAPI.as_view(), name='api_catalogo'),
    path("api/catalogo/<int:id>/", views.CatalogoAPI.as_view(), name='api_catalogo_detalle'),
    path("api/prendas/", views.PrendasAPI.as_view(), name='api_prendas'),

    # API POST, PUT y DELETE
    path("api/prendas/<int:id>/", views.PrendasAPI.as_view(), name='api_prendas_detalles'),

    # SWAGGER
    path("api/schema/", SpectacularAPIView.as_view(), name="api_schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="api_schema"), name="api_docs"),
]