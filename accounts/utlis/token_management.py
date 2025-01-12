from rest_framework_simplejwt.tokens import RefreshToken

class CustomTokenManager:
    @staticmethod
    def create_tokens(user):
        """
        Generate access and refresh tokens for the given user.
        Returns the access token and refresh token.
        """
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        return str(access_token), str(refresh)
