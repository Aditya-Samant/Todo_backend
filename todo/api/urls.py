from django.urls import path,include
from account.views import RegisterView, MyTokenObtainPairViews,TodosViewSet
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
router = DefaultRouter()
router.register(r'todos', TodosViewSet, basename='todos')

urlpatterns = [
    path('account/login/', MyTokenObtainPairViews.as_view(), name='token_obtain_pair'),
    path('account/login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('',include(router.urls)),
    path('account/register/', RegisterView.as_view(), name="sign_up"),
]