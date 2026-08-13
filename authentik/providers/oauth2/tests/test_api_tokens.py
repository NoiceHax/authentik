"""Test OAuth2 token API"""

from dataclasses import asdict
from json import dumps

from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user, create_test_flow, create_test_user
from authentik.lib.generators import generate_id
from authentik.providers.oauth2.id_token import IDToken
from authentik.providers.oauth2.models import (
    AccessToken,
    AuthorizationCode,
    OAuth2Provider,
    RedirectURI,
    RedirectURIMatchingMode,
    RefreshToken,
)


class TestTokenAPI(APITestCase):
    """Test the RBAC behaviour of the OAuth2 token ViewSets"""

    def setUp(self) -> None:
        super().setUp()
        self.provider = OAuth2Provider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            redirect_uris=[RedirectURI(RedirectURIMatchingMode.STRICT, "http://testserver")],
        )
        self.admin = create_test_admin_user()
        self.user = create_test_user()
        self.other_user = create_test_user()
        self.token = self.create_refresh_token(self.user)
        self.other_token = self.create_refresh_token(self.other_user)

    def create_refresh_token(self, user) -> RefreshToken:
        """Create a refresh token for `user`"""
        return RefreshToken.objects.create(
            provider=self.provider,
            user=user,
            token=generate_id(),
            auth_time=timezone.now(),
            _scope="openid",
            _id_token=dumps(asdict(IDToken("foo", "bar"))),
        )

    def test_list_without_permission(self):
        """Test that users without permissions only see their own tokens"""
        self.client.force_login(self.user)
        response = self.client.get(reverse("authentik_api:refreshtoken-list"))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["pagination"]["count"], 1)
        self.assertEqual(body["results"][0]["pk"], self.token.pk)

    def test_list_superuser(self):
        """Test that superusers see all tokens"""
        self.client.force_login(self.admin)
        response = self.client.get(reverse("authentik_api:refreshtoken-list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["pagination"]["count"], 2)

    def test_list_global_permission(self):
        """Test that a global view permission grants access to all tokens"""
        self.user.assign_perms_to_managed_role("authentik_providers_oauth2.view_refreshtoken")
        self.client.force_login(self.user)
        response = self.client.get(reverse("authentik_api:refreshtoken-list"))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["pagination"]["count"], 2)
        self.assertEqual(
            {result["pk"] for result in body["results"]},
            {self.token.pk, self.other_token.pk},
        )

    def test_retrieve_global_permission(self):
        """Test that a global view permission grants access to another user's token"""
        self.user.assign_perms_to_managed_role("authentik_providers_oauth2.view_refreshtoken")
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("authentik_api:refreshtoken-detail", kwargs={"pk": self.other_token.pk})
        )
        self.assertEqual(response.status_code, 200)

    def test_retrieve_without_permission(self):
        """Test that another user's token is not accessible without permissions"""
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("authentik_api:refreshtoken-detail", kwargs={"pk": self.other_token.pk})
        )
        self.assertEqual(response.status_code, 404)

    def test_delete_global_permission(self):
        """Test that global permissions allow deleting another user's token"""
        self.user.assign_perms_to_managed_role(
            [
                "authentik_providers_oauth2.view_refreshtoken",
                "authentik_providers_oauth2.delete_refreshtoken",
            ]
        )
        self.client.force_login(self.user)
        response = self.client.delete(
            reverse("authentik_api:refreshtoken-detail", kwargs={"pk": self.other_token.pk})
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(RefreshToken.objects.filter(pk=self.other_token.pk).exists())

    def test_delete_without_permission(self):
        """Test that another user's token cannot be deleted without permissions"""
        self.client.force_login(self.user)
        response = self.client.delete(
            reverse("authentik_api:refreshtoken-detail", kwargs={"pk": self.other_token.pk})
        )
        self.assertEqual(response.status_code, 404)
        self.assertTrue(RefreshToken.objects.filter(pk=self.other_token.pk).exists())

    def test_delete_own(self):
        """Test that users can delete their own tokens"""
        self.client.force_login(self.user)
        response = self.client.delete(
            reverse("authentik_api:refreshtoken-detail", kwargs={"pk": self.token.pk})
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(RefreshToken.objects.filter(pk=self.token.pk).exists())

    def test_access_token_global_permission(self):
        """Test that a global view permission grants access to all access tokens"""
        AccessToken.objects.create(
            provider=self.provider,
            user=self.other_user,
            token=generate_id(),
            auth_time=timezone.now(),
            _scope="openid",
            _id_token=dumps(asdict(IDToken("foo", "bar"))),
        )
        self.user.assign_perms_to_managed_role("authentik_providers_oauth2.view_accesstoken")
        self.client.force_login(self.user)
        response = self.client.get(reverse("authentik_api:accesstoken-list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["pagination"]["count"], 1)

    def test_authorization_code_global_permission(self):
        """Test that a global view permission grants access to all authorization codes"""
        AuthorizationCode.objects.create(
            provider=self.provider,
            user=self.other_user,
            code=generate_id(),
            auth_time=timezone.now(),
            _scope="openid",
        )
        self.user.assign_perms_to_managed_role("authentik_providers_oauth2.view_authorizationcode")
        self.client.force_login(self.user)
        response = self.client.get(reverse("authentik_api:authorizationcode-list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["pagination"]["count"], 1)
