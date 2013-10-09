#!/usr/bin/python
#
# Copyright (c) 2011 Red Hat, Inc.
#
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

import glob
import os
import sys
import shutil

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)) + "/../common/")
import testutil

import mocks
from pulp.cds.cdslib import loginit, CdsLib, SecretFile
from pulp.cds.lb import storage

# test root dir
ROOTDIR = '/tmp/pulp-cds'

TEST_STORAGE_FILE = '/tmp/cds-plugin-storage-test'
TEST_LOCK_FILE = '/tmp/cds-plugin-storage-lock'

class TestCdsPlugin(testutil.PulpAsyncTest):

    def clean(self):
        testutil.PulpAsyncTest.clean(self)

    def setUp(self):
        testutil.PulpAsyncTest.setUp(self)

        if not self.config.has_section('cds'):
            self.config.add_section('cds')
        self.packages_dir = os.path.join(ROOTDIR, 'packages')
        self.config.set('cds', 'packages_dir', self.packages_dir)
        self.config.set('cds', 'sync_threads', '3')
        self.config.set('cds', 'verify_size', 'false')
        self.config.set('cds', 'verify_checksum', 'false')
        self.config.set('cds', 'log_config_file', '/../../etc/pulp/logging/unit_tests.cfg')
        if not self.config.has_section('server'):
            self.config.add_section('server')
        self.config.set('server', 'ca_cert_file', os.path.join(ROOTDIR, "empty_ca_cert_file"))

        if os.path.exists(TEST_STORAGE_FILE):
            os.remove(TEST_STORAGE_FILE)

        if os.path.exists(TEST_LOCK_FILE):
            os.remove(TEST_LOCK_FILE)

        self.storage_default_file = storage.DEFAULT_FILE_STORE
        self.storage_default_lock = storage.DEFAULT_FILE_LOCK

        storage.DEFAULT_FILE_STORE = TEST_STORAGE_FILE
        storage.DEFAULT_FILE_LOCK = TEST_LOCK_FILE
        
    def tearDown(self):
        testutil.PulpAsyncTest.tearDown(self)
        shutil.rmtree(ROOTDIR, True)
        storage.DEFAULT_FILE_STORE = self.storage_default_file
        storage.DEFAULT_FILE_LOCK = self.storage_default_lock

    def test_initialize(self):
        cds = CdsLib(self.config)
        cds.initialize()

    def test_release(self):
        cds = CdsLib(self.config)
        cds.release()

    def test_secret(self):
        uuid = 'mysecret'
        path = os.path.join(ROOTDIR, 'gofer/.secret')
        secret = SecretFile(path)
        secret.write(uuid)
        f = open(path)
        s = f.read()
        f.close()
        self.assertEqual(uuid, s)
        s = secret.read()
        self.assertEqual(uuid, s)
        secret.delete()
        self.assertFalse(os.path.exists(path))

    def test_basic_sync(self):
        base_url = "http://jmatthews.fedorapeople.org"
        repo = {
            "name":"cdsplugin_test_basic_sync_repo_name",
            "id":"cdsplugin_test_basic_sync_repo_id",
            "relative_path":"repo_multiple_versions"
        }

        self.config.remove_option("cds", "cds_remove_old_versions")
        self.config.remove_option("cds", "num_old_pkgs_keep")
        cds = CdsLib(self.config)

        sync_data = {}
        sync_data['repos'] = [repo]
        sync_data['repo_base_url'] = base_url
        sync_data['repo_cert_bundles'] = {repo["id"]:None}
        sync_data['global_cert_bundle'] = {}
        sync_data['cluster_id'] = "test_cluster"
        sync_data['cluster_members'] = ["test_cds_hostname_1"]
        sync_data['server_ca_cert'] = None

        cds.sync(sync_data)
        # Find the number of .rpms under self.packages_dir
        synced_rpms = glob.glob("%s/*.rpm" % (os.path.join(self.packages_dir, "repos", repo["relative_path"])))
        self.assertEqual(len(synced_rpms), 12)

    def test_sync_with_remove_old_sync_data(self):
        base_url = "http://jmatthews.fedorapeople.org"
        repo = {
            "name":"cdsplugin_test_basic_sync_repo_name",
            "id":"cdsplugin_test_basic_sync_repo_id",
            "relative_path":"repo_multiple_versions"
        }

        self.config.remove_option("cds", "cds_remove_old_versions")
        self.config.remove_option("cds", "num_old_pkgs_keep")
        cds = CdsLib(self.config)

        sync_data = {}
        sync_data['repos'] = [repo]
        sync_data['repo_base_url'] = base_url
        sync_data['repo_cert_bundles'] = {repo["id"]:None}
        sync_data['global_cert_bundle'] = {}
        sync_data['cluster_id'] = "test_cluster"
        sync_data['cluster_members'] = ["test_cds_hostname_1"]
        sync_data['server_ca_cert'] = None
        sync_data['cds_remove_old_versions'] = 'true'
        sync_data['num_old_pkgs_keep'] = '5'

        cds.sync(sync_data)
        # Find the number of .rpms under self.packages_dir
        synced_rpms = glob.glob("%s/*.rpm" % (os.path.join(self.packages_dir, "repos", repo["relative_path"])))
        self.assertEqual(len(synced_rpms), 6)

    def test_cds_confg_sync_options_overrule_sync_data_options(self):
        base_url = "http://jmatthews.fedorapeople.org"
        repo = {
            "name":"cdsplugin_test_basic_sync_repo_name",
            "id":"cdsplugin_test_basic_sync_repo_id",
            "relative_path":"repo_multiple_versions"
        }

        self.config.set("cds", "cds_remove_old_versions", "true")
        self.config.set("cds", "num_old_pkgs_keep", "1")
        cds = CdsLib(self.config)

        sync_data = {}
        sync_data['repos'] = [repo]
        sync_data['repo_base_url'] = base_url
        sync_data['repo_cert_bundles'] = {repo["id"]:None}
        sync_data['global_cert_bundle'] = {}
        sync_data['cluster_id'] = "test_cluster"
        sync_data['cluster_members'] = ["test_cds_hostname_1"]
        sync_data['server_ca_cert'] = None
        sync_data['cds_remove_old_versions'] = 'false'
        sync_data['num_old_pkgs_keep'] = '0'

        cds.sync(sync_data)
        # Find the number of .rpms under self.packages_dir
        synced_rpms = glob.glob("%s/*.rpm" % (os.path.join(self.packages_dir, "repos", repo["relative_path"])))
        self.assertEqual(len(synced_rpms), 2)


    def test_basic_priv_sync(self):
        base_url = "http://jmatthews.fedorapeople.org"
        repo = {
            "name":"cdsplugin_test_basic_sync_repo_name",
            "id":"cdsplugin_test_basic_sync_repo_id",
            "relative_path":"repo_multiple_versions"
        }
        self.config.remove_option('cds', 'cds_remove_old_versions')
        self.config.remove_option('cds', 'num_old_pkgs_keep')

        cds = CdsLib(self.config)
        report = cds._sync_repo(base_url, repo)
        synced_rpms = glob.glob("%s/*.rpm" % (os.path.join(self.packages_dir, "repos", repo["relative_path"])))
        self.assertEqual(len(synced_rpms), 12)
        self.assertEqual(report.downloads, 12)

    def test_priv_sync_with_remove_old_packages(self):
        base_url = "http://jmatthews.fedorapeople.org"
        repo = {
            "name":"cdsplugin_test_basic_sync_repo_name",
            "id":"cdsplugin_test_basic_sync_repo_id",
            "relative_path":"repo_multiple_versions"
        }
        self.config.set('cds', 'cds_remove_old_versions', 'true')
        self.config.set('cds', 'num_old_pkgs_keep', '2')
        cds = CdsLib(self.config)
        report = cds._sync_repo(base_url, repo)
        # Repo has 12 versions of the same package, we expect to 
        # Sync latest versions + 'num_old_pkgs_keep'
        # this means we expect 3 packages to be synced
        synced_rpms = glob.glob("%s/*.rpm" % (os.path.join(self.packages_dir, "repos", repo["relative_path"])))
        self.assertEqual(len(synced_rpms), 3)
        self.assertEqual(report.downloads, 3)

