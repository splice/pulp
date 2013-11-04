source ./env_vars

setenforce 0
sed -i "s/^SELINUX.*/SELINUX=permissive/" /etc/selinux/config

service iptables stop
chkconfig iptables off



rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm

wget -O /etc/yum.repos.d/testing_rpms_rhui.repo http://${RHUI_BUILD_HOST}/pub/testing_rpms_rhui.repo

yum groupinstall -y "Development Tools"
#
# We will install latest pulp RPMs to bring down all the deps, then we'll remove the pulp RPMs later.
# pulp-v1 requires an older version of mongodb, we must disable epel when installing pulp
#  if you do not disable epel, then there will be a conflict with pymongo
#
yum --disablerepo=epel install -y pulp pulp-admin pulp-consumer gofer gofer-package
yum install -y python-nose python-paste python-mock rpmlint

# Note, pulp v1 requires mongodb-server-1.8.2, don't install a newer mongo
# pymongo 1.9 is required
chkconfig mongod on
service mongod restart
echo "Sleeping 60 seconds to allow mongo initializations to complete"
sleep 60

service pulp-server init

# Removing pulp RPMs since we will now run from git checkout
# Note:  the pulp v1 git checkout is shared with the host machine, it's accessible at /vagrant
rpm -e --nodeps pulp pulp-admin pulp-consumer

# Below will run through the Pulp v1 development environment setup steps
pushd .
cd ${PULP_GIT_PATH}/src
python setup.py develop
cd ..
python pulp-dev.py -I
popd

pulp-migrate

# Update /etc/pulp/pulp.conf
sed -i "s/^server_name:.*/server_name: ${VM_HOSTNAME}/" /etc/pulp/pulp.conf
sed -i "s/^url:.*/url: tcp:\/\/${VM_HOSTNAME}:5672/" /etc/pulp/pulp.conf

# Update /etc/pulp/admin/admin.conf
sed -i "s/^host.*/host = ${VM_HOSTNAME}/" /etc/pulp/admin/admin.conf

service qpidd restart
service pulp-server restart

pulp-admin auth login --username admin --password admin
pulp-admin repo create --id simple_errata --feed http://repos.fedorapeople.org/repos/pulp/pulp/demo_repos/test_errata_install/

# Note, Pulp intentionally locks down all config files under /etc/pulp 
# and prevents non-root/apache from reading.  This creates problems
# when we want to run the unit tests as a non-root user, eg: vagrant
# Therefore we are intentionally changing the permissions, just from the devel-env
chmod -R a+rX /etc/pulp

echo "Pulp devel enviroment is setup"


