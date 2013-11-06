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

from ConfigParser import SafeConfigParser
from os import listdir
from os.path import exists, isfile, join
from pulp.repo_auth import oid_validation, identity_validation, auth_enabled_validation

# -- constants --------------------------------------------------------------------

CONFIG_FILENAME = '/etc/pulp/repo_auth.conf'

REQUIRED_PLUGINS = []

# The auth_enabled_validation runs first to prevent other plugins from running in
# case the config indicates repo auth should not be run
OPTIONAL_PLUGINS = (auth_enabled_validation.authenticate,
                    oid_validation.authenticate)


def check_password(environ, user, password):
    '''
    Hook into mod_wsgi to be invoked when a request is determining authentication.
    If the authentication is successful, this method populates the user inside of
    the request and returns True. If validation fails, False is returned.

    @return: True if the request is authorized, otherwise False.
    @rtype:  Boolean
    '''
    _load_plugins(environ)
    authorized = _handle(environ)
    return authorized
    
    
# -- private -----------------------------------------------------------------------

def _handle(environ):
    '''
    Performs the logic of authenticating the request against all registered plugins. The
    logic is as follows:

    - *All* required plugins must indicate that the authentication is valid
    - If any optional plugins are defined, *at least one* must indicate the authentication
      is valid

    Both of the above operations will short-circuit once the minimum requirements are met;
    there is no guarantee that every plugin will run on every request.

    @return: True if the request is authorized, otherwise False.
    @rtype:  Boolean
    '''

    # First apply to the required handlers; if any of these fail we are immediately
    # unauthorized
    for f in REQUIRED_PLUGINS:
        result = f(environ)

        if not result:
            environ["wsgi.errors"].write('Authorization failed by plugin [%s]' % f.__module__)
            return False

    # If we get this far, the required plugins have passed. Run the optional plugins
    # and ensure that at least one of them passes.
    if len(OPTIONAL_PLUGINS) == 0:
        return True

    for f in OPTIONAL_PLUGINS:
        result = f(environ)

        if result:
            return True

    return False


def _load_plugins(environ):
    '''
    Load required authentication plugins dynamically.
    '''

    config = SafeConfigParser()
    config.read(CONFIG_FILENAME)

    required_plugin_path = config.get('plugins', 'required_path')
    
    if exists(required_plugin_path):
        filenames = [f for f in listdir(required_plugin_path) if isfile(join(required_plugin_path, f)) and f.endswith('.py') and not f.startswith('__')]   
        for f in filenames:
            module_name = f[:-3]
            try:
                parent = __import__('pulp.repo_auth', globals(), locals(), [module_name], -1)
            except ImportError, e:
                environ["wsgi.errors"].write("Could not import any plugins from %s. Import error was: '%s'" % (module_name, e))
                continue
            
            module = parent.__dict__[module_name]
            REQUIRED_PLUGINS.append(module)
