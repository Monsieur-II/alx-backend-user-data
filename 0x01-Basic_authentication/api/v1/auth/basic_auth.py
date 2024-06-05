#!/usr/bin/env python3
"""this module for basic authentication"""

from api.v1.auth.auth import Auth
from typing import List
from flask import request, jsonify, abort


class BasicAuth(Auth):
    """BasicAuth class"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """extract base64 authorization header"""
        if authorization_header is None or type(authorization_header) is not str:
            return None
        if authorization_header[:6] != "Basic ":
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """decode base64 authorization header"""
        if base64_authorization_header is None or type(base64_authorization_header) is not str:
            return None
        try:
            import base64
            base64_bytes = base64_authorization_header.encode('utf-8')
            message_bytes = base64.b64decode(base64_bytes)
            message = message_bytes.decode('utf-8')
            return message
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """extract user credentials"""
        if decoded_base64_authorization_header is None or type(decoded_base64_authorization_header) is not str:
            return (None, None)
        if ":" not in decoded_base64_authorization_header:
            return (None, None)
        credentials = decoded_base64_authorization_header.split(":", 1)
        return (credentials[0], credentials[1])

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """user object from credentials"""
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        from models.user import User
        users = User.search({'email': user_email})
        if users is None or users == []:
            return None
        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """current user"""
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None
        base64_auth_header = self.extract_base64_authorization_header(auth_header)
        if base64_auth_header is None:
            return None
        decoded_auth_header = self.decode_base64_authorization_header(base64_auth_header)
