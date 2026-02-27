import secrets

class AuthHelpers:
    @staticmethod
    def generate_token():
        return secrets.token_urlsafe(16)
