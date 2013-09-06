#!/usr/bin/python
#
# Copyright (c) 2011 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

# Python
import shutil
import sys
import os
import urlparse

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)) + "/../common/")
import testutil

import pulp.repo_auth.oid_validation as oid_validation
from pulp.repo_auth.oid_validation import OidValidator
from pulp.server.api.repo import RepoApi
from pulp.server.api.auth import AuthApi

# -- constants ------------------------------------------------------------------

CERT_TEST_DIR = '/tmp/test_oid_validation/'

# -- mocks ----------------------------------------------------------------------

def mock_environ(client_cert_pem, uri):
    environ = {}
    environ["mod_ssl.var_lookup"] = lambda *args: client_cert_pem
    # Set REQUEST_URI the same way that it will be set via mod_wsgi
    path = urlparse.urlparse(uri)[2]
    environ["REQUEST_URI"] = path
    
    class Errors:
        def write(self, *args, **kwargs):
            pass

    environ["wsgi.errors"] = Errors()
    return environ

# -- test cases -----------------------------------------------------------------

class TestOidValidation(testutil.PulpAsyncTest):

    def clean(self):
        testutil.PulpAsyncTest.clean(self)
        if os.path.exists(CERT_TEST_DIR):
            shutil.rmtree(CERT_TEST_DIR)

        protected_repo_listings_file = self.config.get('repos', 'protected_repo_listing_file')
        if os.path.exists(protected_repo_listings_file):
            os.remove(protected_repo_listings_file)

    def setUp(self):
        testutil.PulpAsyncTest.setUp(self)
        self.validator = OidValidator(self.config)

    # See https://fedorahosted.org/pulp/wiki/RepoAuth for more information on scenarios

    def test_scenario_1(self):
        '''
        Setup
        - Global auth disabled
        - Individual repo auth enabled for repo X
        - Client cert signed by repo X CA
        - Client cert has entitlements

        Expected
        - Permitted for both repos
        '''

        # Setup
        self.auth_api.disable_global_repo_auth()

        repo_x_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.repo_api.create('repo-x', 'Repo X', 'noarch', consumer_cert_data=repo_x_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(FULL_CLIENT_CERT, 'https://localhost//pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ(FULL_CLIENT_CERT, 'https://localhost//pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(response_x)
        self.assertTrue(response_y)

    def test_scenario_2(self):
        '''
        Setup
        - Global auth disabled
        - Individual repo auth enabled for repo X
        - Client cert signed by different CA than repo X
        - Client cert has entitlements

        Expected
        - Denied to repo X, permitted for repo Y
        '''

        # Setup
        self.auth_api.disable_global_repo_auth()

        repo_x_bundle = {'ca' : INVALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.repo_api.create('repo-x', 'Repo X', 'noarch', consumer_cert_data=repo_x_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(not response_x)
        self.assertTrue(response_y)

    def test_scenario_3(self):
        '''
        Setup
        - Global auth disabled
        - Individual repo auth enabled for repo X
        - Client cert signed by repo Y CA
        - Client cert does not have entitlements for requested URL

        Expected
        - Permitted to repo X, denied from repo Y
        '''

        # Setup
        self.auth_api.disable_global_repo_auth()

        repo_y_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.repo_api.create('repo-x', 'Repo X', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch', consumer_cert_data=repo_y_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(LIMITED_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ(LIMITED_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(response_x)
        self.assertTrue(not response_y)

    def test_scenario_4(self):
        '''
        Setup
        - Global auth enabled
        - Individual auth disabled
        - Client cert signed by global CA
        - Client cert has entitlements to both repo X and Y

        Expected
        - Permitted to repo X and Y
        '''

        # Setup
        global_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT,}
        self.auth_api.enable_global_repo_auth(global_bundle)

        self.repo_api.create('repo-x', 'Repo X', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(response_x)
        self.assertTrue(response_y)

    def test_scenario_5(self):
        '''
        Setup
        - Global auth enabled
        - Individual auth disabled
        - Client cert signed by global CA
        - Client cert has entitlements to only repo X

        Expected
        - Permitted to repo X, denied to repo Y
        '''

        # Setup
        global_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.auth_api.enable_global_repo_auth(global_bundle)

        self.repo_api.create('repo-x', 'Repo X', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(LIMITED_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ(LIMITED_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(response_x)
        self.assertTrue(not response_y)

    def test_scenario_6(self):
        '''
        Setup
        - Global auth enabled
        - Individual auth disabled
        - Client cert signed by non-global CA
        - Client cert has entitlements for both repos

        Expected
        - Denied to both repo X and Y
        '''

        # Setup
        global_bundle = {'ca' : INVALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.auth_api.enable_global_repo_auth(global_bundle)

        self.repo_api.create('repo-x', 'Repo X', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(not response_x)
        self.assertTrue(not response_y)

    def test_scenario_7(self):
        '''
        Setup
        - Global auth enabled
        - Individual auth enabled on repo X
        - Both global and individual auth use the same CA
        - Client cert signed by the specified CA
        - Client cert has entitlements for both repos

        Expected
        - Permitted for both repo X and Y
        '''

        # Setup
        global_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.auth_api.enable_global_repo_auth(global_bundle)

        repo_x_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.repo_api.create('repo-x', 'Repo X', 'noarch', consumer_cert_data=repo_x_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(response_x)
        self.assertTrue(response_y)

    def test_scenario_8(self):
        '''
        Setup
        - Global auth enabled
        - Individual auth enabled on repo X
        - Different CA certificates for global and repo X configurations
        - Client cert signed by repo X's CA certificate
        - Client cert has entitlements for both repos

        Expected
        - Permitted for repo X, denied for repo Y
        '''

        # Setup
        global_bundle = {'ca' : INVALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.auth_api.enable_global_repo_auth(global_bundle)

        repo_x_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.repo_api.create('repo-x', 'Repo X', 'noarch', consumer_cert_data=repo_x_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(response_x)
        self.assertTrue(not response_y)

    def test_scenario_9(self):
        '''
        Setup
        - Global auth enabled
        - Individual auth enabled for repo X
        - Different CA certificates for global and repo X configurations
        - Client cert signed by global CA certificate
        - Client cert has entitlements for both repos

        Excepted
        - Denied for repo X, passes for repo Y
        '''

        # Setup
        global_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.auth_api.enable_global_repo_auth(global_bundle)

        repo_x_bundle = {'ca' : INVALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.repo_api.create('repo-x', 'Repo X', 'noarch', consumer_cert_data=repo_x_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ(FULL_CLIENT_CERT, 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(not response_x)
        self.assertTrue(response_y)

    def test_scenario_10(self):
        '''
        Setup
        - Global auth disabled
        - Individual repo auth enabled for repo X
        - No client cert in request

        Expected
        - Denied for repo X, permitted for repo Y
        - No exceptions thrown
        '''

        # Setup
        self.auth_api.disable_global_repo_auth()

        repo_x_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.repo_api.create('repo-x', 'Repo X', 'noarch', consumer_cert_data=repo_x_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ('', 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ('', 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(not response_x)
        self.assertTrue(response_y)

    def test_scenario_11(self):
        '''
        Setup
        - Global auth enabled
        - Individual auth disabled
        - No client cert in request

        Expected
        - Denied to both repo X and Y
        - No exceptions thrown
        '''

        # Setup
        global_bundle = {'ca' : INVALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.auth_api.enable_global_repo_auth(global_bundle)

        self.repo_api.create('repo-x', 'Repo X', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ('', 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ('', 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(not response_x)
        self.assertTrue(not response_y)

    def test_scenario_12(self):
        '''
        Setup
        - Global auth enabled
        - Individual auth enabled on repo X
        - Both global and individual auth use the same CA
        - No client cert in request

        Expected
        - Denied for both repo X and Y
        - No exceptions thrown
        '''

        # Setup
        global_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.auth_api.enable_global_repo_auth(global_bundle)

        repo_x_bundle = {'ca' : VALID_CA, 'key' : ANYKEY, 'cert' : ANYCERT, }
        self.repo_api.create('repo-x', 'Repo X', 'noarch', consumer_cert_data=repo_x_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ('', 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/')
        request_y = mock_environ('', 'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(not response_x)
        self.assertTrue(not response_y)

    def test_scenario_13(self):
        repo_x_bundle = {'ca' : VALID_CA, 'key' : ANYKEY2, 'cert' : ANYCERT2, }
        self.repo_api.create('repo-x', 'Repo X', 'noarch', consumer_cert_data=repo_x_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch', consumer_cert_data=repo_x_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(FULL_WILDCARD_CLIENT, 
            'https://localhost/pulp/repos/repos/pulp/pulp/fedora-14/x86_64/os')
        request_y = mock_environ(FULL_WILDCARD_CLIENT, 
            'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/os')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(response_x)
        self.assertTrue(response_y)

        # Try to hit something that should be denied
        request_z = mock_environ(FULL_WILDCARD_CLIENT, 
            'https://localhost/pulp/repos/repos/pulp/pulp/fedora-13/x86_64/mrg-g/2.0/os')
        response_z = oid_validation.authenticate(request_z, config=self.config)
        self.assertTrue(not response_z)

    def test_scenario_14(self):
        '''
        Setup
        - Global auth disabled
        - Individual repo auth enabled for repo X
        - Client cert signed by repo X CA
        - Client cert has an OID entitlement that ends with a yum variable.
          e.g., repos/pulp/pulp/fedora-14/$basearch/

        Expected
        - Permitted for both repos
        '''

        # Setup
        self.auth_api.disable_global_repo_auth()

        repo_x_bundle = {'ca' : VALID_CA2, 'key' : VALID_CA2_KEY, 'cert' : ANYCERT, }
        self.repo_api.create('repo-x', 'Repo X', 'noarch', consumer_cert_data=repo_x_bundle,
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-14/x86_64')
        self.repo_api.create('repo-y', 'Repo Y', 'noarch',
                             feed='http://repos.fedorapeople.org/repos/pulp/pulp/fedora-13/x86_64')

        # Test
        request_x = mock_environ(ENDS_WITH_VARIABLE_CLIENT +
            ENDS_WITH_VARIABLE_CLIENT_KEY, 
            'https://localhost//pulp/repos/repos/pulp/pulp/fedora-14/x86_64/os/repodata/repomd.xml')
        request_xx = mock_environ(ENDS_WITH_VARIABLE_CLIENT +
            ENDS_WITH_VARIABLE_CLIENT_KEY, 
            'https://localhost//pulp/repos/repos/pulp/pulp/fedora-14/i386/os/repodata/repomd.xml')
        request_y = mock_environ(ENDS_WITH_VARIABLE_CLIENT +
            ENDS_WITH_VARIABLE_CLIENT_KEY, 
            'https://localhost//pulp/repos/repos/pulp/pulp/fedora-13/x86_64/os/repodata/repomd.xml')

        response_x = oid_validation.authenticate(request_x, config=self.config)
        response_xx = oid_validation.authenticate(request_xx, config=self.config)
        response_y = oid_validation.authenticate(request_y, config=self.config)

        # Verify
        self.assertTrue(response_x)
        self.assertTrue(response_y)


# -- test data ---------------------------------------------------------------------

ANYCERT = """
-----BEGIN CERTIFICATE-----
MIIC9zCCAd8CAmlJMA0GCSqGSIb3DQEBBQUAMG4xCzAJBgNVBAYTAlVTMRAwDgYD
VQQIEwdBbGFiYW1hMRMwEQYDVQQHEwpIdW50c3ZpbGxlMRYwFAYDVQQKEw1SZWQg
SGF0LCBJbmMuMSAwHgYJKoZIhvcNAQkBFhFqb3J0ZWxAcmVkaGF0LmNvbTAeFw0x
MTA2MDMyMDQ5MjdaFw0yMTA1MzEyMDQ5MjdaMBQxEjAQBgNVBAMTCWxvY2FsaG9z
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMRkjseAow6eH/IgWb5z
D47QRA0No9jNqGL6onRSYaMjCTKcu3T1nPbBTVlxSQw9cah2anXoJaFZzIcc7c0R
PGMpJR3wVe/0sOBMTeD0CFHwdhin2lo75AMLldc/7qenuMT9bxaQKZ3MDRbalz+E
SIXFZPx/Oy2cp5vWwq3OEQAcRwMhdYZfRjoKZ+xQ+kHhdJD4Baakee8vyP2o3T+x
LY2ZOBBLtuhypB96QrCESozL8u2YS3Dqbq1X0ge0eub/lk+QMDjrtF5kTC45jgJE
ykdRFhgKznO5IAwnHt5NvZ1wQxF/lAvt6lBG5t9XuFV1cQOLiE7BzklDjOX97Oy9
JxMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAZwck2cMAT/bOv9Xnyjx8qzko2xEm
RlHtMDMHpzBGLRAaj9Pk5ckZKJLeGNnGUXTEA2xLfN5Q7B9R9Cd/+G3NE2Fq1KfF
XXPux/tB+QiSzzrE2U4iOKDtnVEHAdsVI8fvFZUOQCr8ivGjdWyFPvaRKI0wA3+s
XQcarTMvR4adQxUp0pbf8Ybg2TVIRqQSUc7gjYcD+7+ThuyWLlCHMuzIboUR+NRa
kdEiOVJc9jJOzj/4NljtFggxR8BV5QbCt3w2rRhmnhk5bN6OdqxbJjH8Wmm6ae0H
rwlofisIJvB0JQxaoQgprDem4CChLqEAnMmCpybfSLLqXTieTPr116nQ9A==
-----END CERTIFICATE-----
"""

ANYKEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxGSOx4CjDp4f8iBZvnMPjtBEDQ2j2M2oYvqidFJhoyMJMpy7
dPWc9sFNWXFJDD1xqHZqdegloVnMhxztzRE8YyklHfBV7/Sw4ExN4PQIUfB2GKfa
WjvkAwuV1z/up6e4xP1vFpApncwNFtqXP4RIhcVk/H87LZynm9bCrc4RABxHAyF1
hl9GOgpn7FD6QeF0kPgFpqR57y/I/ajdP7EtjZk4EEu26HKkH3pCsIRKjMvy7ZhL
cOpurVfSB7R65v+WT5AwOOu0XmRMLjmOAkTKR1EWGArOc7kgDCce3k29nXBDEX+U
C+3qUEbm31e4VXVxA4uITsHOSUOM5f3s7L0nEwIDAQABAoIBAQCxBnt09U0FZh8h
n2uFsi15690Lbxob2PVJkuZQt9lutawaxRBsEuETw5Y3Y1gXAmOrGGJKOaGB2XH0
8GyiBkFKmNHuNK8iBoxRAjbI6O9+/KNXAiZeY9HZtN2yEtzKnvJ8Dn3N9tCsfjvm
N89R36mHezDWMNFlAepLHMCK7k6Aq2XfMSgHJMmHYv2bBdcnbPidl3kr8Iq3FLL2
0qoiou+ihvKEj4SAguQNuR8w5oXKc5I3EdmXGGJ0WlZM2Oqg7qL85KhQTg3WEeUj
XB4cLC4WoV0ukvUBuaCFCLdqOLmHk2NB3b4DEYlEIsz6XiE3Nt7cBO2HBPa/nTFl
qAvXxQchAoGBAPpY1S1SMHEWH2U/WH57jF+Yh0yKPPxJ6UouG+zzwvtm0pfg7Lkn
CMDxcTTyMpF+HjU5cbJJrVO/S1UBnWfxFdbsWFcw2JURqXj4FO4J5OcVHrQEA6KY
9HBdPV6roTYVIUeKZb6TxIC85b/Xkcb3AHYtlDg3ygOjFKD6NUVNHIebAoGBAMjT
1bylHJXeqDEG+N9sa1suH7nMVsB2PdhsArP3zZAoOIP3lLAdlQefTyhpeDgYbFqD
wxjeFHDuJjxIvB17rPCKa8Rh4a0GBlhKEDLm+EM3H0FyZ0Yc53dckgDOnJmyh9f+
8fc7nYqXEA7sD0keE9ANGS+SLV9h9v9A7og7bGHpAoGAU/VU0RU+T77GmrMK36hZ
pHnH7mByIX48MfeSv/3kR2HtgKgbW+D+a47Nk58iXG76fIkeW1egPHTsM78N5h0R
YPn0ipFEIYJB3uL8SfShguovWNn7yh0X5VMv0L8omrWtaou8oZR3E2HGf3cxWZPe
4MNacRwssNmRgodHNE2vIr8CgYABp50vPL0LjxYbsU8DqEUKL0sboM9mLpM74Uf0
a6pJ8crla3jSKqw7r9hbIONYsvrRlBxbbBkHBS9Td9X0+Dvoj3tr1tKhNld/Cr0v
bi/FfgLH60Vmkn5lwWGCmDE6IvpzkSo1O0yFA9GiDdfiZlkLcdAvUCkHjCsY11Qf
0z2FYQKBgQDCbtiEMMHJGICwEX2eNiIfO4vMg1qgzYezJvDej/0UnqnQjbr4OSHf
0mkVJrA0vycI+lP94eEcAjhFZFjCKgflZL9z5GLPv+vANbzOHyIw+BLzX3SybBeW
NgH6CEPkQzXt83c+B8nECNWxheP1UkerWfe/gmwQmc0Ntt4JvKeOuw==
-----END RSA PRIVATE KEY-----
"""

# Entitlements for:
#  - repos/pulp/pulp/fedora-14/x86_64/
LIMITED_CLIENT_CERT = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwCREYb08c9LX3gBcjMWruCnTKq6ndRzP5+C0tdqlH2o9icwP
fT5Zz+GpApMDeB0HCB/Yei2kFoiMGXFDRVhBX/uJ9628ByKVYsz5NvsJd6cHlZEV
zG/jmJ2eI+8aHP+VeTt0G+LFHqJ00fLLYgdkhVjOOlwoAKYyQXR4e+H9KUN2vo97
DoQR+NXyJlnB0fOMYGSXhxgL2Kq52XL9+sP1UEgv3yi+Zc7rXXs6nKRTqsqtSqCu
GGspcAwiab1gagVQeLs4gkUHvPW+0wNZJdPsTWKQYE6z7AHAwdA7U+I0HspexECH
QHAJlGlTPO4uGshhDzwVktj4KM3jIYRW/PiLGwIDAQABAoIBAQCws+nLdUwWPK5X
tT9oGxY8bQKNu0e31YKCfk3S/LxkssDbbDZGeUQBgUd8XZWQLincV+UvH7BLJNKr
R1WVfX/J9LvCcx179lsqHNWIsb/YMV0xONeyRqgqH7Ji267JQmfFsV6rkpa0ALWs
qzxN7/yLAcvPMhd72VxYg/OWApRfD9hYwvncbPfaciK2WoS2C7ROk6yE/pRpsgXl
ztTtjDA6yEMW4+nvFRlVwIsOmGKhJFgGHTrxAAYQfeeec5Cr58EOC9nrVSPFODgY
V0090wqptcqBS5VOI35BpffOx5gJF5kj7YMIRaG6Mc8X/j7xaBSr7UqzYcY2nQ8L
mgZ3Wf+pAoGBAPnsNgLxrFIHiNVKFY3vkdqVCeg+WwY8U8TXykatUhCW6KxUc7DP
5jLo5rHAvb0TuA0C6YyXDjXQRPVNR1xf04d97YtWYl2qSyzrz4SkXCIQX5vruWNA
5z15Pdf8ufzBD8M/kI0K58ZZc/F5zt3qe1LzmYbC673JMHsO1gDL2WIPAoGBAMTQ
XVLBHWhEv09TsR/0+9wQaO4rZXZsM3vbNBgSQGGp9yQYk88LsQ0e/4rP7wbryfWf
c0TEVmkGzzDUmNlO4x8zP6UhUljikEfrCUfVNLHXgwP88sQCiwf8qgPNi6NLxaq9
MohL+00qeMWzuUfOPUEPiuWPV3jV16ZDBXPHOuI1AoGAGrKyHmRkzSqC4o4UeWIj
SZ9sPIQUwzjElh2bPSucvarxVh97cGL1K3EX29tEKaOmoLUz79HfMb56711/Bw4x
kaLRMnZa8biUaUsTkw7fzL/FBuoKluDDEx0VjzIvSCHzph7vOTH2ColZym0BvVEk
NXtSZkQCXPbWF/9AuzsLkN8CgYAqc6ctimoFa464VZ0G/5izxvZbKREhkgUo2gdK
ieVJK5gbORHovuTZp64HCwLLw2A0ksgSNSdOUCGwrqqpdNKYkD1SKPXSJkxottGx
pNNQ6ONhoNXcYZALkPw7BcLw3g8s3NJhg8IYyuhx/GoiiuG7fta+3URI1BdHzX0H
lBmnYQKBgQC2PTzHXp8X1/YITHLNLpswrAN6AX8WygTMBysIlVnUDvfSc4KC0aKZ
R4/8g6/zfoEEgKL384NcP3VLYw8z3osRkz0fPu1GzkiW7ywANjqSlYLx8tBQwemc
KLKIOWvKeAlhU09ogPPsBjm2yWSHNsqQjhualWMog2WCbM+jfKWz8g==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIEXTCCA0WgAwIBAgIBAzANBgkqhkiG9w0BAQUFADBkMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCTkMxEDAOBgNVBAcMB1JhbGVpZ2gxEDAOBgNVBAoMB1JlZCBIYXQx
DTALBgNVBAsMBFB1bHAxFTATBgNVBAMMDFB1bHAtUm9vdC1DQTAeFw0xMzA5MDUy
MjE3MDRaFw00MzA4MjkyMjE3MDRaMGkxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJO
QzEQMA4GA1UEBwwHUmFsZWlnaDEQMA4GA1UECgwHUmVkIEhhdDENMAsGA1UECwwE
UHVscDEaMBgGA1UEAwwRUHVscF9Db250ZW50X0NlcnQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDAJERhvTxz0tfeAFyMxau4KdMqrqd1HM/n4LS12qUf
aj2JzA99PlnP4akCkwN4HQcIH9h6LaQWiIwZcUNFWEFf+4n3rbwHIpVizPk2+wl3
pweVkRXMb+OYnZ4j7xoc/5V5O3Qb4sUeonTR8stiB2SFWM46XCgApjJBdHh74f0p
Q3a+j3sOhBH41fImWcHR84xgZJeHGAvYqrnZcv36w/VQSC/fKL5lzutdezqcpFOq
yq1KoK4YaylwDCJpvWBqBVB4uziCRQe89b7TA1kl0+xNYpBgTrPsAcDB0DtT4jQe
yl7EQIdAcAmUaVM87i4ayGEPPBWS2PgozeMhhFb8+IsbAgMBAAGjggETMIIBDzAJ
BgNVHRMEAjAAMCsGDCsGAQQBkggJAgIBAQQbDBlQdWxwIFByb2R1Y3Rpb24gRmVk
b3JhIDE0MB8GDCsGAQQBkggJAgIBAgQPDA1wdWxwLXByb2QtZjE0MDEGDCsGAQQB
kggJAgIBBgQhDB9yZXBvcy9wdWxwL3B1bHAvZmVkb3JhLTE0L2kzODYvMCsGDCsG
AQQBkggJAgMBAQQbDBlQdWxwIFByb2R1Y3Rpb24gRmVkb3JhIDE0MB8GDCsGAQQB
kggJAgMBAgQPDA1wdWxwLXByb2QtZjE0MDMGDCsGAQQBkggJAgMBBgQjDCFyZXBv
cy9wdWxwL3B1bHAvZmVkb3JhLTE0L3g4Nl82NC8wDQYJKoZIhvcNAQEFBQADggEB
AImLqfQgdFJmX7OfnUfnF+lidq06jBqfAXlP8GkS/AW0kMLI5GZgEpr1n7XKb7pC
8+IcYAxFs+6dGwkcrilBqbhfy7EuGVN7gu1yCA1I5jiOC/PQHR+ct46qgip18URP
HfEa4qc0OIlMblaeIjEbdiAWzEM4SjQ1Aov4fy5XQqu2UQwo29FKBXHoy20FqXWX
hh1eLAFWadArCVsLVKjsVm6sdFEFL0I6n4a9xLkKKFt2+urQuQnkmWcVcBcmigGc
FUsIsMDk7ECFmPqv0nU95cpiRlSPdC4jwR7807noGJ66QvDwUP881dJkCDsYt/1a
1AisVnJJQJY6JVPq5EHpn5g=
-----END CERTIFICATE-----
'''

# Entitlements for:
#  - repos/pulp/pulp/fedora-13/x86_64/
#  - repos/pulp/pulp/fedora-14/x86_64/
FULL_CLIENT_CERT = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAq6GJmZV3zTlnhsjJhCi0HjAA3RT37x3NSlAyUSfIKbeMLJa0
lBZVtucA9HuDo69k2jEOqbKb19QwnF3kLCaPPFGCZvKNLxd4iz4I4SCInwSbQtG1
unfFtia89fJucGArjw2vu+S8F1AsjW3E8R3gNE0Ow0+PyjAIK7prqO5s0rkVmrju
xRpLubphyXyKYvze7vN5qA0+xoSfsOm4z4+a80sK35iq20+oKCApD5nRplrn6EgP
tXhU2QmQ5RwmC7q4JzRApB9KUyPiacbkPdQXCiggpevQ+nDSNUExSoubxsTzFgWI
O74jeX4Wjd+Jeo7ADOkHKWffatMKuVbJgVFidQIDAQABAoIBAGBKIIip8qyQqCRW
QbiDnYnSJKnkObVNYv9uPsyJJSNCdsINSwJKBYy3zTFcml4a6NoA69kI+6X6xcr0
Yi7i8zlEAYUAT3U8FcUI6LJlLkEItJKoVOxohePLl/fkK1Ggos9/PjiL+3qY4GX4
T6V2vXKaSM4KtQEaMXtW+0+rdCJECUOhKXjpUWUhrxvQS1mPbOLWkhMDlXr0eVmT
LOAPcrkY36QGbfWgerlc+d1uLYcHXSRZ6Z3gw1owPB3k1wKnRsWFpSWCtQpjbu8r
zLX8mnX8j1zTAwt65GkhhU30u3/UTml6lqLjrxdJZ1DG1F9NXqU7GFKbmhgmg1ss
KP950AECgYEA1AleLQ72/H3tAsaJRaNeZMCG1I0tzbtJN/PDLTqp0Ql+nknAkjbW
fC1M69I3bS3ZjBnB6BZ7HVC2tPMlZraFNCljjeb7U8hfKBeu44mIrDdeM0pANYYY
0Wj3dGdu4DnhNj4N7gHDOt5dXOp+EZZfmzJ6VHwyzR6XqbwjAXu7/FUCgYEAzzd+
F08Shw5wxGdwNfmVhTG+C4cBBo3yoVjNYR2ASGfS751gjIb2fue40I0XdF1ml+G/
UVeevXjQXUuGFixyuHvVv5VtTZEPMLjXpDqUYcgoIqdoGVktHUnoRc2Kuy8z2O6h
YInIbhmCUoVtPbJ8sYjuKHGUkLZIHCGiQyaJ7aECgYBDmLzyRmwM8KRHlz2Z+swT
+KDDUELC7KsZ8FdPqv0KTCmWktKWim70ZYi5QWo0H0LUfD2qHMig/uNQapeI2DU8
/NjlGzcSbbWQVYSGu4jbxkb8uPYhWh+9WuZQsMzTJQCcR0ovj1ZLBSrkfUk1mCfg
lUYUewfDBra5AOZ0CZtThQKBgQC+FTOPgjOGvJJpOFHQ0XB9TFH/FQq1zoShyWot
CfjhcowmzgEBJ9T6OOpqNOMtFXjFHop3vZ6aRDcvPdZ0hLV/0ekT46junICIuybl
Oe9fe1KF53cwuYMO+Pse/Ruj9frjppNWkU3Q4YmQ1WCOVirYWLnPU9Fqpiuj0p6c
Zr/jwQKBgA0usI5oQ3g9QzXMp+d1b0p+0nZDeU4zfJ3AyQlYu2mA5ge36JaddphV
fKcMwUDRXsIXlG6agaoAQetDCFTz74MZ/zV5Cn3ChdAh6m9Vc+doSdU1kXxiJoST
ckv8PCIwcWCxSNNnuh3LxaZEQBw3ADULzZHZFfVzdkI50hxbbM1Q
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIHaTCCBlGgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBkMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCTkMxEDAOBgNVBAcMB1JhbGVpZ2gxEDAOBgNVBAoMB1JlZCBIYXQx
DTALBgNVBAsMBFB1bHAxFTATBgNVBAMMDFB1bHAtUm9vdC1DQTAeFw0xMzA5MDUy
MTU5MzRaFw00MzA4MjkyMTU5MzRaMGkxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJO
QzEQMA4GA1UEBwwHUmFsZWlnaDEQMA4GA1UECgwHUmVkIEhhdDENMAsGA1UECwwE
UHVscDEaMBgGA1UEAwwRUHVscF9Db250ZW50X0NlcnQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCroYmZlXfNOWeGyMmEKLQeMADdFPfvHc1KUDJRJ8gp
t4wslrSUFlW25wD0e4Ojr2TaMQ6pspvX1DCcXeQsJo88UYJm8o0vF3iLPgjhIIif
BJtC0bW6d8W2Jrz18m5wYCuPDa+75LwXUCyNbcTxHeA0TQ7DT4/KMAgrumuo7mzS
uRWauO7FGku5umHJfIpi/N7u83moDT7GhJ+w6bjPj5rzSwrfmKrbT6goICkPmdGm
WufoSA+1eFTZCZDlHCYLurgnNECkH0pTI+JpxuQ91BcKKCCl69D6cNI1QTFKi5vG
xPMWBYg7viN5fhaN34l6jsAM6QcpZ99q0wq5VsmBUWJ1AgMBAAGjggQfMIIEGzAJ
BgNVHRMEAjAAMCsGDCsGAQQBkggJAgABAQQbDBlQdWxwIFByb2R1Y3Rpb24gRmVk
b3JhIDE1MB8GDCsGAQQBkggJAgABAgQPDA1wdWxwLXByb2QtZjE1MDEGDCsGAQQB
kggJAgABBgQhDB9yZXBvcy9wdWxwL3B1bHAvZmVkb3JhLTE1L2kzODYvMCsGDCsG
AQQBkggJAgEBAQQbDBlQdWxwIFByb2R1Y3Rpb24gRmVkb3JhIDE1MB8GDCsGAQQB
kggJAgEBAgQPDA1wdWxwLXByb2QtZjE1MDMGDCsGAQQBkggJAgEBBgQjDCFyZXBv
cy9wdWxwL3B1bHAvZmVkb3JhLTE1L3g4Nl82NC8wKwYMKwYBBAGSCAkCAgEBBBsM
GVB1bHAgUHJvZHVjdGlvbiBGZWRvcmEgMTQwHwYMKwYBBAGSCAkCAgECBA8MDXB1
bHAtcHJvZC1mMTQwMQYMKwYBBAGSCAkCAgEGBCEMH3JlcG9zL3B1bHAvcHVscC9m
ZWRvcmEtMTQvaTM4Ni8wKwYMKwYBBAGSCAkCAwEBBBsMGVB1bHAgUHJvZHVjdGlv
biBGZWRvcmEgMTQwHwYMKwYBBAGSCAkCAwECBA8MDXB1bHAtcHJvZC1mMTQwMwYM
KwYBBAGSCAkCAwEGBCMMIXJlcG9zL3B1bHAvcHVscC9mZWRvcmEtMTQveDg2XzY0
LzArBgwrBgEEAZIICQIEAQEEGwwZUHVscCBQcm9kdWN0aW9uIEZlZG9yYSAxNjAf
BgwrBgEEAZIICQIEAQIEDwwNcHVscC1wcm9kLWYxNjAxBgwrBgEEAZIICQIEAQYE
IQwfcmVwb3MvcHVscC9wdWxwL2ZlZG9yYS0xNi9pMzg2LzArBgwrBgEEAZIICQIF
AQEEGwwZUHVscCBQcm9kdWN0aW9uIEZlZG9yYSAxNjAfBgwrBgEEAZIICQIFAQIE
DwwNcHVscC1wcm9kLWYxNjAzBgwrBgEEAZIICQIFAQYEIwwhcmVwb3MvcHVscC9w
dWxwL2ZlZG9yYS0xNi94ODZfNjQvMCsGDCsGAQQBkggJAgYBAQQbDBlQdWxwIFBy
b2R1Y3Rpb24gRmVkb3JhIDEzMB8GDCsGAQQBkggJAgYBAgQPDA1wdWxwLXByb2Qt
ZjEzMDEGDCsGAQQBkggJAgYBBgQhDB9yZXBvcy9wdWxwL3B1bHAvZmVkb3JhLTEz
L2kzODYvMCsGDCsGAQQBkggJAgcBAQQbDBlQdWxwIFByb2R1Y3Rpb24gRmVkb3Jh
IDEzMB8GDCsGAQQBkggJAgcBAgQPDA1wdWxwLXByb2QtZjEzMDMGDCsGAQQBkggJ
AgcBBgQjDCFyZXBvcy9wdWxwL3B1bHAvZmVkb3JhLTEzL3g4Nl82NC8wDQYJKoZI
hvcNAQEFBQADggEBAGMVx+h83dtUoP7dr3UoCbIjy/YVf5suvcrMVC5h+AyoFsIU
iNt8djY1l7OwldkbkKdfmW3JI0ThvyJQSOsKFrsA+nsfAePH3m2tvpvvF06Iyt1t
NOwVlBFdYUMufD3Mv8K/RtKtjERrFFp5YdBa90z16zioFvIG6UjDJ9+znkq/q7VD
Hq4kndlcrb14YnDDsqshhzx/bQSbPgJUsdGGhHmwpvOXsGVViElrVUJP4Hj++sxO
UzMLYaQhhoytTXSQKrNjj5snjbvPJK0B45er4H9JLxpyCfyPzg7b6TfYUhFiDLrt
Rv+u6YiYuBAvGZJvjYVg/6G6zqkc6br250LxvDk=
-----END CERTIFICATE-----
'''

VALID_CA = '''
-----BEGIN CERTIFICATE-----
MIIDmzCCAoOgAwIBAgIJAJ++RCe4FrVyMA0GCSqGSIb3DQEBBQUAMGQxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJOQzEQMA4GA1UEBwwHUmFsZWlnaDEQMA4GA1UECgwH
UmVkIEhhdDENMAsGA1UECwwEUHVscDEVMBMGA1UEAwwMUHVscC1Sb290LUNBMB4X
DTEzMDkwNTIxNTgyMFoXDTQzMDgyOTIxNTgyMFowZDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgMAk5DMRAwDgYDVQQHDAdSYWxlaWdoMRAwDgYDVQQKDAdSZWQgSGF0MQ0w
CwYDVQQLDARQdWxwMRUwEwYDVQQDDAxQdWxwLVJvb3QtQ0EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDNeKFYhiCt9tLAKjE9mtZcFlenMhYoEMEB7V4+
fXcC3YnM6bZAovHHNJPW13stV1Ezf4IA2oaF2ek9DGSzo7TIh+kFUyau2j+ThatI
PvBKWaPw+GyxLXAX+b1OhLP7P0j9SOEfc31C409r3ElP6YWLcPpukrx6xEHd5wW4
7e12/xLdpec1DpbJaCHgm2RBPMosaZaw+WNibHlWkC6j78MKNE+zIIr69X4wpR4n
vQ/SNKGHgvdPfdPMSn27suI6xQ4+RpyP4yiGTRh1gHb2iNUyl0jN16K7RvSJGveu
iX9WPfM7cajPTTRTdYwtwkrQSnbD3W5PidUxc9NC93Vc1t+VAgMBAAGjUDBOMB0G
A1UdDgQWBBRsCjA+qcKgrM2txdIGTe7tA8kRSTAfBgNVHSMEGDAWgBRsCjA+qcKg
rM2txdIGTe7tA8kRSTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAl
07FFlW9RI4vRXg8jBlF1Upijz7vJp9TxqUeoDDyk2YllZSktLM8OEdJEcYd3901s
TA+3vpYHVhFVJgCni5eVC3nZaDm5xSC0wNmvAG1efb5eRMdbA5RFtsKSL2AySvXM
T2i2+TJDJf5YXpLvtbCmyh90hrjspxjKq/5/+meMM9qOkDEmvwjBy34oF2R05tl3
JURGkEtzE/qDGr855gotuFx5TR5pPxihWoBU4NJfa6O6XT5122NLxBmJLU7MFweg
vzJEN6WzPjI3/QNylmeYCUlUaRlzfbrcxb4t/NVYjuXceRtRS0TsMmkOSQTjzhG7
n9nr6YhL2V94MgvpJ3ak
-----END CERTIFICATE-----
'''

INVALID_CA = '''
-----BEGIN CERTIFICATE-----
MIIFnTCCA4WgAwIBAgIJAII71LRLCAczMA0GCSqGSIb3DQEBBQUAMGUxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJOSjESMBAGA1UEBwwJTWlja2xldG9uMRAwDgYDVQQK
DAdSZWQgSGF0MQ8wDQYDVQQLDAZQdWxwIDIxEjAQBgNVBAMMCXB1bHAtY2EtMjAe
Fw0xMTAzMjUyMDA0MTBaFw0xMjAzMjQyMDA0MTBaMGUxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIDAJOSjESMBAGA1UEBwwJTWlja2xldG9uMRAwDgYDVQQKDAdSZWQgSGF0
MQ8wDQYDVQQLDAZQdWxwIDIxEjAQBgNVBAMMCXB1bHAtY2EtMjCCAiIwDQYJKoZI
hvcNAQEBBQADggIPADCCAgoCggIBALIZrAAZFxKqzpMXiIwClv/o1tyFn6hnUhEX
HXaCHoY5QZZ695UXz9b0dxNKaMgfEq9fjfdP3f8A1yg9lTIyiG4BAPpSla/RT/B6
fBwLF2WBvCbPJB7w5+ZLCHkDIOd6swBQUEHXGOIEk1IUByEndlksHzzUpVL8BDq4
gMfDCmsV5SsfcQN8ophgXN6fOPHtluOmfIjxoCq69aB0NjjDzYbW9Vo/2VLeNbdv
XEfZRBgJv/VpSAQF8POB3yHUw95GN5OjECXhMBQ2mlyyNksVSFIn2yOBwr7tejVA
61pjZio1CMN5JLc63DZQkBNEtGknG6qmcVhZUjhINsK5R1S/Mh3oyT9/c1W+yPii
oJOe7PEemlWSwt4ufFnXbRMbUDx9g0ud6nUxnXPA9RugkfkXvsXKct4ql1WI64jL
3sDUNN65aj8W8LG+WOEYuXvuyXkFl/lMT9wzLG9Y85xB6S1wnggS/4zVikptHEFK
KjLOlCWYPQNmbjUiekkRk/qnAixTqLcNXssVj4GlW9ElZeu4mNidk/lXoeVzyIBJ
710OjUH7EuMe87gPf3q0x/Cm6E98O6b9Zqhm6/4nQSrd1YT5kqRfCWMyKP8bdSpU
HAT6Zx3b1df4mdZZ6JW7MF5cXHaGxZzdA7WVpq6YAg7JJxBt9B2KOQyj1kXOeWuD
RU1qIJCtAgMBAAGjUDBOMB0GA1UdDgQWBBT2RGJP7ERHn5q5rR7gOsfybW5zMDAf
BgNVHSMEGDAWgBT2RGJP7ERHn5q5rR7gOsfybW5zMDAMBgNVHRMEBTADAQH/MA0G
CSqGSIb3DQEBBQUAA4ICAQBI2Yi0q2S2giGy/banh3Ab3Qg1XirkGa3HmA2JF7XV
dcsPjzDwKd3DEua76gZ94w+drEve0z95YPC02jiK2/9EOyoIS+Sc3ro698mUuUuY
A0vxAQJEoQNlCtNs7St60L98wWp64oTiTPTBjYBoQsBYul9Omh/qkmMqz/L/t47T
nc3AcVzrDwesNlyWUMPg1SajXth4ux6+7/GiWaE8QRZiX6LjN6362dN8J7P39iBj
Ftw1duPZTYg5gkmuYjy+CfSvSyzq/TKV5JYVWijpAzAM9iyoBQFLEfzA8Vb+C+kk
DTKhBObJF1aGxJHFkIqN2XnKaBAQYzR3y7duUJS7OmufSVwsJgzT1jUCZ/qFLFlW
TSiSdWGGR2NzsMoO4mCLBFpHe2PENFy//US1OQERNBHZKFx3t8YyLh8tzda5goXM
4K+FIH1+WeoibKr+UnQC4CU3Ujbf3/Ut7+MDu5A76djkPjgIbJChe3YoExBzJck3
DAK56kpnnuqwj0EyAqpsEiF4CAcpBwLP7LVc68XGfzIzRaRJOlerEscFR2USmW+c
+ITpNVXEGdZgdBjIIq/n+59JqEHnKinRaQMZBNppD6WZ6NVelcb4094kc1H1Qpkt
f/LU796X0sQbbbpuKab4CNNYaj7ig5wnbC5ONYmYTebcOML+H9b/iOomNCPDmLpj
tA==
-----END CERTIFICATE-----
'''

VALID_CA2 = '''
-----BEGIN CERTIFICATE-----
MIIFlzCCA3+gAwIBAgIJAK7gLD9A4byOMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJOQzEQMA4GA1UEBwwHUmFsZWlnaDEQMA4GA1UECgwH
dGVzdC1jYTEQMA4GA1UECwwHdGVzdC1jYTEQMA4GA1UEAwwHdGVzdC1jYTAeFw0x
MTEwMjQxODM3NDFaFw0zOTAzMTExODM3NDFaMGIxCzAJBgNVBAYTAlVTMQswCQYD
VQQIDAJOQzEQMA4GA1UEBwwHUmFsZWlnaDEQMA4GA1UECgwHdGVzdC1jYTEQMA4G
A1UECwwHdGVzdC1jYTEQMA4GA1UEAwwHdGVzdC1jYTCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBALse+W5GQZbKVlXaWhR/d19KzORVLt141K5YuDUec8yV
wWQjbzaFzCR5PR93078qWTFAhnTjR7L7Q3VN22I47AN7ndX7hB0DjNaXU4glb0L8
U1kgcYn3hn109WHLmBQ6vZh/NDxcrXXJRwLPN3wuxY5H2riEuAyyPO3sIt1GZqgZ
lPAwRVTM/izpQzf1vF8BPQu7BeyKhzy77VViZmnM5VMjOnqVuJHxXVKrJz9sBkWw
gjynn50MDGfMSdTbicBVenEYt8UzJ9BxGfbhOw44f4AUHf0cakewPaauBn+2hNwM
ULprLc+L33sMzHWwXLTJbZY4F/6nc9ocoBU99eBvUSsuIdOixszYKdiGcx+LYRsj
1Y3x1spTmkBAZxAlJP33hnp5XvHYNKqEKf83ysOzmxS9ypL+pSXaZk80CHvOPTAN
qlugMU32avI8E826pILxAxS7M/PO9BjM6d3ll6myghU7rgHWg4J8ppNBGq6nG00s
Zg1rfAy5C7B1DSeTP6X/sW2d/VMvt4IdwJSTKaOlGMQ/xt8BsebMQguQrJNDytpn
Z7G13TPyHsoukaeTh/DjNBEQBBdPXPyRGnZKplrWl6CefVJVnua/t2akKSU0QUwd
LgSWJh66CGq8FnZWzgzimWG63jTqOPFwbC/exQ3HA/wKQm0a92nc03drXLfL9c2P
AgMBAAGjUDBOMB0GA1UdDgQWBBT09Bd6VJIChSReb9CiRJNJFVUxQTAfBgNVHSME
GDAWgBT09Bd6VJIChSReb9CiRJNJFVUxQTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3
DQEBBQUAA4ICAQADUVzB3UtPqWDCaItSjcJzqM4o4ma/c9vIoaiirrM+o1jcNdMF
LKKHrSATG8KVXI//DJBv3VnCnuxUtcFnIgDy7+j0F+WBHQgGab6QHwwMdsnv8UL8
+7BezKzR5kX5tvSaZ6HWuY7fi3Zgy31B8HV5G2FhzFq7m/RUB0ffb/iZb6S4HyZm
XaBAA/Hc+ng9iXSB9ZvyS08xP7jDu2n322FF3xJA9ji20nYfz03VJTrHXe4lapoh
9Ew9qV84gLzVneuxjJ53CplpLD7U3eSiZqK//9TpNflW2vGc/8N9xcX21EX2Mpjn
1A9b9h9MVfptothSeBJodml4F8cMRqmvCq/9gnK2lAWpJhLO3gV94NTIE+2pyX9i
nD9Ts13ng0od5P+C5btCHn4TEACRqUxTM6WknqAgSpx8khOGsj5uljLFRBYEWeRo
xnLEuPaOpXOsfpRcyLsXcTKm/0ixYfaM3O+39seHUiClRT8T9k+0EXEQl6aSIWBB
69FIAf9PZEC+t8aPqA+CRlXw2Xqc1zg7usuPvkxMR/iMhhJ7YTlW8WyFI3BNnQy2
pJ7VHLshUiH3txA3rVlwthJbzuHONzjMKvYzYBeuSIVrri+OWNI1VUeSuDTVz2B4
yJ+DXKvc8zaaoXMu6WxcJOR5p55WZcR93laAMiZSt8YEUltDlrK7G8kVMw==
-----END CERTIFICATE-----
'''

VALID_CA2_KEY = '''
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
'''

WILDCARD_CLIENT = '''
-----BEGIN CERTIFICATE-----
MIID6zCCAtOgAwIBAgIBBjANBgkqhkiG9w0BAQUFADBkMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCTkMxEDAOBgNVBAcMB1JhbGVpZ2gxEDAOBgNVBAoMB1JlZCBIYXQx
DTALBgNVBAsMBFB1bHAxFTATBgNVBAMMDFB1bHAtUm9vdC1DQTAeFw0xMzA5MDUy
MjQ3MDBaFw00MzA4MjkyMjQ3MDBaMGkxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJO
QzEQMA4GA1UEBwwHUmFsZWlnaDEQMA4GA1UECgwHUmVkIEhhdDENMAsGA1UECwwE
UHVscDEaMBgGA1UEAwwRUHVscF9Db250ZW50X0NlcnQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDRaN78y8swl1OJ09xK+tRxW3Fkp9FkZcSd8yPcWV3y
jVO1VVIkK1E/7/+TZEe6QJ2irgINZl4xZpUt+hLfD0AX1Ohop9kht+lZ9NKaq/+N
v0qllTnctc/w/njJnb954vpuWynSkT4aa/AdiftwdETZOG3aIN+cPjHtVN61iKIf
1kJRi7Zi8mox7RoCz4lVrPqnKsDLeBUJGBuXsB/0AR3lnXyo0GvvEmxDkTbqkAW3
3N/uY3k31vazGskfRptIbNK1oo+cv0jG2oUgRd8G3CJ1uZQjHr54DPD1fD40eETB
yXbgrPTqIElHi6NVTy7JYMLm71lnF2oq2UUOMYlzZAwxAgMBAAGjgaIwgZ8wCQYD
VR0TBAIwADAvBgwrBgEEAZIICQIAAQEEHwwdUHVscCBQcm9kdWN0aW9uIE15UmVw
byB4ODZfNjQwJQYMKwYBBAGSCAkCAAECBBUME3B1bHAtcHJvZC1teXJlcG8tNjQw
OgYMKwYBBAGSCAkCAAEGBCoMKHJlcG9zL3B1bHAvcHVscC8kcmVsZWFzZXZlci8k
YmFzZWFyY2gvb3MwDQYJKoZIhvcNAQEFBQADggEBADzqOBdHp5nlKs+ffGc0Ex6H
Ocyt4LsRA4y1k+oMTpZlHYYYntiwr2m5tmUrvXR7djMpsF2vPdF3oWVJiX+aiym5
A+jaFn257MFonk63zQIoNrZQMmr/9phKkTvIEafpy/Kw2Oy2PJuslxoDXntzjeKN
j/mvmIlAy49I2F9DoD/Zid/meuNJxAMcn9WzMVYbvn3GtjliRGYIJXOVrcX+c4lB
lTlTZHV0ST8Gpj0vdiN7kAenselhWA0WunMdmUEqegIizjKKju4SKFiIFOL1Zi93
h0jJRlnhFzOkUv/HF3SqqGHfCaFWEZwIqzWZrfU1iTe+nULEI2KrYi8Sy6Jjpp8=
-----END CERTIFICATE-----
'''


WILDCARD_CLIENT_KEY = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEA0Wje/MvLMJdTidPcSvrUcVtxZKfRZGXEnfMj3Fld8o1TtVVS
JCtRP+//k2RHukCdoq4CDWZeMWaVLfoS3w9AF9ToaKfZIbfpWfTSmqv/jb9KpZU5
3LXP8P54yZ2/eeL6blsp0pE+GmvwHYn7cHRE2Tht2iDfnD4x7VTetYiiH9ZCUYu2
YvJqMe0aAs+JVaz6pyrAy3gVCRgbl7Af9AEd5Z18qNBr7xJsQ5E26pAFt9zf7mN5
N9b2sxrJH0abSGzStaKPnL9IxtqFIEXfBtwidbmUIx6+eAzw9Xw+NHhEwcl24Kz0
6iBJR4ujVU8uyWDC5u9ZZxdqKtlFDjGJc2QMMQIDAQABAoIBAQCPTWTLOeriZawV
NZYa+WtH53vBldYFDl9ud2Si9cUEpxIRlUGQ3tPLHUGYa5dqLa2yFcHxyYvL4pdT
zz36x0TlCh3BAJvmJyTZGmDE188aAT3j8iqWjxStpnaiAgF2N42I13nXTu1gx1yZ
2kLmwaobvDHwg26CTU19TAbb05Sek5LA5MfDbIJyBr/vnKGe0RYDbV/f6KgLEL7O
UzIcsQWjEYSPeuOH4F8IyWdz44XF2P7m84CKpZ+0JueRM9G7ugfx6xLVMX+/vFx/
0pKbYxeaMv9bqRCQJSnPdrrzBH3vIAOAECBiklcrPF2jYRw2tfX1O/1m4Lj6modL
nOfR/4UBAoGBAP1cDHqPcUPMPqGeiB1mIzSNprDIBw35DvEAbgtXgKn8pyFLmA+c
gzrRcJsa9gMjv4fSViiL/n8ScPONcypPQWa3NvZiiMOjQTcAD47QLogzhtYnMQ04
ADLlbUnMhmivgdlI591WV7+DZq1+Y/K6Y/V4lW0JOOsP+UjPQF6TvuP1AoGBANOX
kOcGQo4Q38cVHWcHolBwoEPQP2O9+HzimDPwO/ECfnzJFbqmvnaH6EGXdj6e5g/e
BlTKrh9BRsPOIWvFIqIVsUG7Ja/f8erfAeApldbq6rgOJYRar4c85hIIaoCJkcLa
9/XzwaH7j9uhCnjXFKim9xai7QTW/wblgVvsqd3NAoGBAMQATfcSuUEF5P4LMqnr
thiV7PqeBDcfEhwHhRppGzRmLLVpUb3iCvOZy09y0BcltKpSYi0EAGI11gPUzd9R
aPsZif+Zwsv2pCD0fxSwoQ7lLc7Giv/67sxxCNcqzmB2RjHeYOGuRjv2X5ygRpok
7+ea3Z54n/vZY7ScAOQp0GdxAoGBAMtCUiRb0xt+AjnQgsoyfy4ewxXhusMp/saZ
NfTO1gYTi0Z8NK909ooOzIIV6bUGF6MueY6ClPnZTw1RurE4Uqi5henKyc1Fp7Mk
Pz0DNbmbOZdNn6ShKPUU/z5bb1PC048HoiNW4a+lZPBqpxCmLGZG3h2UrXN0xM/v
MHEJy7QRAoGBAOE3DFF3VaBtp24ijnu1HwDdJt166oAp0rZjA6ruv5lzDdY9ZUh1
hNaDNhmDjUxyNy9sWbjjaEub3ZUxgeBUnryGEn2jbQv7+vLYyOpWPGpyGQK6f58p
kDW3JHZpPH81zCIa3nofZkRFDaz3bqa3YPEbEexMX1p7a4J7WVrgCk6x
-----END RSA PRIVATE KEY-----
'''

# Grants access to:
# repos/pulp/pulp/$releasever/$basearch/os
FULL_WILDCARD_CLIENT = '\n'.join((WILDCARD_CLIENT_KEY, WILDCARD_CLIENT))

ANYKEY2 = '''
-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBALHtPMOOqLs1oDwjD2A0jt5sLYhreJre0USH/ZnuIQvDq6sb6msF
ud0/5mRSRolY61TRorKvHQ3OawtZS3C4R0MCAwEAAQJAHo5mjBMY6SW5gfpnbpc4
HfyoCTCjwr0XZVSRefkKVdGYLYMm1LdeRjSTOVLqNVB3QQbEjEKCVCZQ0xvWTwlk
CQIhAOp40LB8SbFTFA/+rIh6jkhjnsU+tqGawMZZDTR19muVAiEAwkNYbwAs/Mo/
o5YGGk7fdVlfUb/2PWKGg2MyPc8R8XcCIB/G8/GXRp2DtupcB6IPig0Bg1kUIMhS
IuI+221Kt3TpAiA1j0XRjNXaeJSlMJbMKBTaEOMD8g4dDI4TqYTPn8jNrwIgEQ8j
nctWK1z+N+TUw1s9urJD99DNKpnXpcYzz3SU6r0=
-----END RSA PRIVATE KEY-----
'''

ANYCERT2 = '''
-----BEGIN CERTIFICATE-----
MIIDezCCAWMCCQCILWwuj/w7QDANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCTkMxEDAOBgNVBAcMB1JhbGVpZ2gxEDAOBgNVBAoMB3Rlc3Qt
Y2ExEDAOBgNVBAsMB3Rlc3QtY2ExEDAOBgNVBAMMB3Rlc3QtY2EwHhcNMTExMDI0
MTg0MTUxWhcNMzkwMzExMTg0MTUxWjBlMQswCQYDVQQGEwJVUzELMAkGA1UECAwC
TkMxEDAOBgNVBAcMB1JhbGVpZ2gxETAPBgNVBAoMCHRlc3QtYW55MREwDwYDVQQL
DAh0ZXN0LWFueTERMA8GA1UEAwwIdGVzdC1hbnkwXDANBgkqhkiG9w0BAQEFAANL
ADBIAkEAse08w46ouzWgPCMPYDSO3mwtiGt4mt7RRIf9me4hC8OrqxvqawW53T/m
ZFJGiVjrVNGisq8dDc5rC1lLcLhHQwIDAQABMA0GCSqGSIb3DQEBBQUAA4ICAQBz
ofMtaNgR+6gYJhgBU3kFhW3SNS+6b1BCDrJZ6oLfae9bIfC/ri/phpQGEGjZOcoY
zyYRy7xAruW6A5p6QMkJ4inFUeiWeok6gdbmmIkgO2Y0xGnYfSq1eLNBUQ7bpjFU
pAvwpG+ByYYA+yJywC53gzcG14BpzAMCGpp6xXIvW9JBpkYhxcQOfwVw4qSPwRlz
2SJ4L/616MLXuHfiJneYZITtXDQKqePc8f1rqP5l0Ja1/5oatAggBwfBoj4HBSqY
khTByxSoThv4yPAJ9BwC5R3j7yLmtCpgbp3lWVn+mtwJ0u+roznvGLnI346bnU3Q
wMGUhyoSGTYdpi44YK2HSHRZgwSzCClkVQHES64jyUIfBjgtWKZaWY9/JYCnFNFY
25uPrkg6em2WGRJgwUnotv/sdMbpJfMSkgYwSvrgEQJxKXNE8aXSylXjBaDq0+4f
ex3AFJ35OYcRkpS3+RRFPifB8NX/YpqQwBgnhwXfntJPxTDE+4Ad9IQTR3Jkr2qT
yHBxNafX9/D7PxcuY8UR0ZRSLaUn9UG6G6UcWZa8HdqMcXI5YecZUC8Pi5D6rVaZ
tvkBDkSXz3GUeyK11pQC9xYWz7Pyy5+5NktBQ8chDZX0ENWHbGqR9xgHIZXJd0Ks
4Y0Tl5d9N8mMNOpaDsn9Lr+E72NmK3A7Phl8jQow3g==
-----END CERTIFICATE-----
'''

# Entitlements for:
#  - repos/pulp/pulp/fedora-13/$basearch/
#  - repos/pulp/pulp/fedora-14/$basearch/
#
# Signed with VALID_CA2
ENDS_WITH_VARIABLE_CLIENT = """
-----BEGIN CERTIFICATE-----
MIIFYjCCA0qgAwIBAgIBZDANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCTkMxEDAOBgNVBAcMB1JhbGVpZ2gxEDAOBgNVBAoMB3Rlc3QtY2Ex
EDAOBgNVBAsMB3Rlc3QtY2ExEDAOBgNVBAMMB3Rlc3QtY2EwHhcNMTIwMjIwMjIy
NTU1WhcNMTQxMTE2MjIyNTU1WjBoMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTkMx
EDAOBgNVBAcMB1JhbGVpZ2gxEjAQBgNVBAoMCVB1bHAgVGVzdDESMBAGA1UECwwJ
UHVscCBUZXN0MRIwEAYDVQQDDAlwdWxwLXRlc3QwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDEZI7HgKMOnh/yIFm+cw+O0EQNDaPYzahi+qJ0UmGjIwky
nLt09Zz2wU1ZcUkMPXGodmp16CWhWcyHHO3NETxjKSUd8FXv9LDgTE3g9AhR8HYY
p9paO+QDC5XXP+6np7jE/W8WkCmdzA0W2pc/hEiFxWT8fzstnKeb1sKtzhEAHEcD
IXWGX0Y6CmfsUPpB4XSQ+AWmpHnvL8j9qN0/sS2NmTgQS7bocqQfekKwhEqMy/Lt
mEtw6m6tV9IHtHrm/5ZPkDA467ReZEwuOY4CRMpHURYYCs5zuSAMJx7eTb2dcEMR
f5QL7epQRubfV7hVdXEDi4hOwc5JQ4zl/ezsvScTAgMBAAGjggEbMIIBFzAJBgNV
HRMEAjAAMCsGDCsGAQQBkggJAgABAQQbDBlQdWxwIFByb2R1Y3Rpb24gRmVkb3Jh
IDEzMB8GDCsGAQQBkggJAgABAgQPDA1wdWxwLXByb2QtZjEzMDYGDCsGAQQBkggJ
AgABBgQmDCRyZXBvcy9wdWxwL3B1bHAvZmVkb3JhLTEzLyRiYXNlYXJjaC8wKwYM
KwYBBAGSCAkCAwEBBBsMGVB1bHAgUHJvZHVjdGlvbiBGZWRvcmEgMTQwHwYMKwYB
BAGSCAkCAwECBA8MDXB1bHAtcHJvZC1mMTQwNgYMKwYBBAGSCAkCAwEGBCYMJHJl
cG9zL3B1bHAvcHVscC9mZWRvcmEtMTQvJGJhc2VhcmNoLzANBgkqhkiG9w0BAQUF
AAOCAgEAtnDZoKeXtCw/hJAhcUNNoN6VL+B3ShtY3qq0hxNl7lgTPU2908gHVFt5
PvoDVKIXTdLEbU4mT9Hfnh1zMGOE2IcqviGZ2LfLdtZnmY/khS2KwpH5MzG1K9+L
eB9F8zEKVa/nnIxw8StsH8z5ejEyOb8z/cOy+lRuHTJZkuiM1sVMOU95ixkJqfJb
WDZCkzdM+bFfYU9wDM58ONZEn9WsynrswQeXqi6uh6K26DxNMqRqkcHCiEi66H1X
FiExl7TNxpNMfHS0XY6ZTuO2bI0XgTmFbAHTd3XCpNPhNblpHrHhx+KXrDqHgZBR
D8MgbvtnhGU/ioUQuwP/h2wOYX7jmOEWWaPishrgEsS0KAvTorDp9esHharcXNnU
ibYPWp0/4gN/RJAjIRf5DWmcXKRibPfg6qXlADG2MnVp7oZVNqan3W2SLseUMNYS
ph5EPvhUxLMxDd5gncX1MDBENDX6mzbhpd1+CPB44n+nCpjR0rZkjOG+Q3G1m77V
09j4IRuYCEtp0NhgQHXV8L0BDofIj8egtE7MmyPCrKIlDTpHZ5cfduzgt0hVpmOt
zTrt2Dm0DZ9LwFANfRpkpI0ZNKg1/pKlxQOijR/EN2imsLvu/fdfR6dov7PBxfoX
PQvdFGUaYghwNKmFU3ij98jodzfd4x3CnHXgu+Bh2PO425Ww4/8=
-----END CERTIFICATE-----
"""

ENDS_WITH_VARIABLE_CLIENT_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxGSOx4CjDp4f8iBZvnMPjtBEDQ2j2M2oYvqidFJhoyMJMpy7
dPWc9sFNWXFJDD1xqHZqdegloVnMhxztzRE8YyklHfBV7/Sw4ExN4PQIUfB2GKfa
WjvkAwuV1z/up6e4xP1vFpApncwNFtqXP4RIhcVk/H87LZynm9bCrc4RABxHAyF1
hl9GOgpn7FD6QeF0kPgFpqR57y/I/ajdP7EtjZk4EEu26HKkH3pCsIRKjMvy7ZhL
cOpurVfSB7R65v+WT5AwOOu0XmRMLjmOAkTKR1EWGArOc7kgDCce3k29nXBDEX+U
C+3qUEbm31e4VXVxA4uITsHOSUOM5f3s7L0nEwIDAQABAoIBAQCxBnt09U0FZh8h
n2uFsi15690Lbxob2PVJkuZQt9lutawaxRBsEuETw5Y3Y1gXAmOrGGJKOaGB2XH0
8GyiBkFKmNHuNK8iBoxRAjbI6O9+/KNXAiZeY9HZtN2yEtzKnvJ8Dn3N9tCsfjvm
N89R36mHezDWMNFlAepLHMCK7k6Aq2XfMSgHJMmHYv2bBdcnbPidl3kr8Iq3FLL2
0qoiou+ihvKEj4SAguQNuR8w5oXKc5I3EdmXGGJ0WlZM2Oqg7qL85KhQTg3WEeUj
XB4cLC4WoV0ukvUBuaCFCLdqOLmHk2NB3b4DEYlEIsz6XiE3Nt7cBO2HBPa/nTFl
qAvXxQchAoGBAPpY1S1SMHEWH2U/WH57jF+Yh0yKPPxJ6UouG+zzwvtm0pfg7Lkn
CMDxcTTyMpF+HjU5cbJJrVO/S1UBnWfxFdbsWFcw2JURqXj4FO4J5OcVHrQEA6KY
9HBdPV6roTYVIUeKZb6TxIC85b/Xkcb3AHYtlDg3ygOjFKD6NUVNHIebAoGBAMjT
1bylHJXeqDEG+N9sa1suH7nMVsB2PdhsArP3zZAoOIP3lLAdlQefTyhpeDgYbFqD
wxjeFHDuJjxIvB17rPCKa8Rh4a0GBlhKEDLm+EM3H0FyZ0Yc53dckgDOnJmyh9f+
8fc7nYqXEA7sD0keE9ANGS+SLV9h9v9A7og7bGHpAoGAU/VU0RU+T77GmrMK36hZ
pHnH7mByIX48MfeSv/3kR2HtgKgbW+D+a47Nk58iXG76fIkeW1egPHTsM78N5h0R
YPn0ipFEIYJB3uL8SfShguovWNn7yh0X5VMv0L8omrWtaou8oZR3E2HGf3cxWZPe
4MNacRwssNmRgodHNE2vIr8CgYABp50vPL0LjxYbsU8DqEUKL0sboM9mLpM74Uf0
a6pJ8crla3jSKqw7r9hbIONYsvrRlBxbbBkHBS9Td9X0+Dvoj3tr1tKhNld/Cr0v
bi/FfgLH60Vmkn5lwWGCmDE6IvpzkSo1O0yFA9GiDdfiZlkLcdAvUCkHjCsY11Qf
0z2FYQKBgQDCbtiEMMHJGICwEX2eNiIfO4vMg1qgzYezJvDej/0UnqnQjbr4OSHf
0mkVJrA0vycI+lP94eEcAjhFZFjCKgflZL9z5GLPv+vANbzOHyIw+BLzX3SybBeW
NgH6CEPkQzXt83c+B8nECNWxheP1UkerWfe/gmwQmc0Ntt4JvKeOuw==
-----END RSA PRIVATE KEY-----
"""
