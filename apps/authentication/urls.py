# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path
from .views import *
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('', landing_page, name="home"),  # Default landing Page Route
    path('login/', login_view, name="login"),
    path('register/', register_user, name="register"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path('forgot-password/', forgot_password_view, name='forgot_password'), # URL Route for Fprgot Password Page.
    path('reset-password/', reset_password_view, name='reset_password'), # URL Route for Reset Password Page.

    # URL Route for Error page 404, 500, and 403.
    path('404/', page_404_view, name='page_404'),
    path('500/', page_500_view, name='page_500'),


    # Path for Dashboard View.
    # Main Dashboard Route
    path('helpdesk_dashbaord/', help_desk_portal, name='helpdesk_portal'),
    path('dashboard/', dashboard_view, name='dashboard'),

    # URL Routes of Main Dashboard Page.
    path('add-user/', add_user_view, name='add_user'),

    # Side Bar Component routes
    path('transactions/', transactions_view, name='transactions'),
    path('settings/', settings_view, name='settings'),          # Url Route fpr Settings Sidebar Section Code.
    path('bootstrap-tables/', bootstrap_tables_view, name='bootstrap_tables'),



    # Temperory Sidebar Component Route for Component Section.
    path('buttons/', buttons_view, name='buttons'),
    path('notifications/', notifications_view, name='components_notifications'),
    path('forms/', forms_view, name='components_forms'),
    path('modals/', modals_view, name='components_modals'),
    path('typography/', typography_view, name='components_typography'),
]