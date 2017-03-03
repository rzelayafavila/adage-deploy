"""Fab tasks to provision an Adage server.

Use these only once to setup an ubuntu server. For day to day usage and 
development you should use the adage-server fabfile. Specify your deployment
configuration parameters in `adage-server/adage/adage/config.py` (using
`config.py.template` as a guide) and then type "fab deploy_aws" to deploy to
your AWS configuration or type "fab deploy_dev" to deploy a development
server from scratch.

If the private key for your aws ubuntu instance is kept in 
~/.ssh/aws_ubuntu.pem, invoking adage_server.setup_host_conn() will attempt to 
use that for connections. (You will see warning messages if this file is 
missing.)

To launch and configure a new ec2 instance, make sure your database 
configuration (in adage-server/adage/adage/config.py under 
AWS_CONFIG['databases']) does not conflict with a running instance, and use: 
> fab deploy_aws
"""

from __future__ import with_statement
import logging
import os, sys
import pprint
import time
from boto3.session import Session
from fabric.api import put, get, run, sudo, execute, reboot
from fabric.api import env, local, settings, hide, abort, task, runs_once
from fabric.contrib.console import confirm

# Now we have to import the fabfile we use for adage-server routine
# deployment. We depend upon some of the commands from that codebase so we can
# allow its configuration to remain self-contained while not repeating code we
# need to use here at deployment time. To achieve this, we carefully manipulate
# the system path to import the fabfile from the adage-server directory. Note
# that in order to access the fabric commands without bashing our heads against
# Python namespace conflicts we must keep the fabric commands for one or
# the other of these deployment scripts in a file named something *other* than
# fabfile.py. We have opted to place the adage-server deployment scripts in a
# fabfile/ package. Currently, everything resides in one large module named
# fabfile/adage-server.py, but this structure will allow us to break up the
# deployment scripts into smaller modules in the future, if we choose. 

# BASE_DIR is equivalent to a relative path of ../../adage-server/
BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), 'adage-server'
)
if BASE_DIR not in sys.path:
    sys.path.insert(0, os.path.join(BASE_DIR, 'fabfile'))

# CONFIG_DIR is equivalent to a path of BASE_DIR/adage/adage/
CONFIG_DIR = os.path.join(BASE_DIR, 'adage', 'adage')
if CONFIG_DIR not in sys.path:
    sys.path.append(CONFIG_DIR)

# Now, finally, we can go ahead and import what we want.
import adage_server
import config

# Choose the configuration to use for the rest of this deployment from config.py
CONFIG = config.CONFIG


@task
def v():
    """ Turn on more verbose logging """
    logging.basicConfig(level=logging.INFO)


@task
def print_config():
    """
    Show what configuration we are currently using
    NOTE: using this command will display passwords and other secrets
    """
    pprint.PrettyPrinter().pprint(CONFIG)


@task(alias='ec2-list')
def list_ec2_instances():
    """
    Show a list of all available ec2 instances
    """
    s = Session(**dict((k,v) for k, v in config.AWS_DEPLOY.items()
        if k in ('aws_access_key_id', 'aws_secret_access_key', 'region_name')))
    ec2 = s.resource('ec2')
    for i in ec2.instances.all():
        print(
            "{0}: state: {1}\n\tdns: {2}\n\timage: {3}\n\tlaunched: {4}"
        ).format(i.id, i.state, i.public_dns_name, i.image_id, i.launch_time)


@task(alias='ec2-new')
def launch_ec2_instance():
    """
    Launch a new ec2 instance, get its IP address and 
    reset env.user and env.hosts to point to just that new instance
    
    (for boto documentation, see: 
    https://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.ServiceResource.create_instances)
    """
    
    s = Session(**dict((k,v) for k, v in config.AWS_DEPLOY.items()
        if k in ('aws_access_key_id', 'aws_secret_access_key', 'region_name')))
    ec2 = s.resource('ec2')
    
    print("Launching new EC2 instance...")
    # do this to setup the ubuntu key; we do it here so we can override
    # env.hosts below
    execute(adage_server.setup_host_conn,
        use_conn=config.AWS_DEPLOY['host_conn'])
    inst = ec2.create_instances(**config.AWS_DEPLOY['ec2_params'])
    inst[0].wait_until_running()
    # override the current env.hosts since we are launching a new instance
    # NOTE: this seems like a convoluted way to get the IP address, but it works
    env.hosts = [
        i.public_ip_address for i in ec2.instances.all() if i.id == inst[0].id
    ]
    env.user = 'ubuntu'
    print("New instance launching at: {0}".format(env.hosts[0]))
    # this is a little hackish, but it ensures the next command will not
    # timeout because the server hasn't actually finished coming online yet...
    print("Waiting for instance to come online...")
    time.sleep(45)
    with settings(hide('running'), warn_only=True):
        # note: this is not actually a "reboot" but a "hostname" command
        execute(reboot, command='hostname', hosts=[
            'ubuntu@' + h for h in env.hosts ])
    print("New instance is now running at: {0}".format(env.hosts[0]))


@task
def enable_unattended_updates():
    """
    Tell ubuntu to install upgrades automatically.

    This enables automatic and unattended upgrades. This also allows automatic
    reboots if required.
    """
    put('files/upgrade/20auto-upgrades',
        '/etc/apt/apt.conf.d/20auto-upgrades', use_sudo=True)
    put('files/upgrade/50unattended-upgrades',
        '/etc/apt/apt.conf.d/50unattended-upgrades', use_sudo=True)


def _install_elasticsearch():
    """
    Install ElasticSearch packages + JRE.

    Add the elastic search repo and key, and the install the ElasticSearch
    package and dependencies.
    """
    run('wget -qO - http://packages.elasticsearch.org/GPG-KEY-elasticsearch |'
        ' sudo apt-key add -')
    run("echo -e "
        "'deb http://packages.elasticsearch.org/elasticsearch/1.7/debian "
        "stable main\n' | sudo tee -a "
        "/etc/apt/sources.list.d/elasticsearch-1.7.list")
    sudo('apt-get update')
    sudo('apt-get -y -q install elasticsearch default-jdk')
    # this plugin lets us use 'network.host: _ec2_' in the config below
    run('cd /usr/share/elasticsearch; '
        'sudo bin/plugin install elasticsearch/elasticsearch-cloud-aws/2.4.2')
    sudo('/bin/systemctl daemon-reload')
    sudo('/bin/systemctl enable elasticsearch.service')


def _install_python_deps():
    """
    Install python and the packages required for development.

    Install mercurial, pip, distribute, and packages needed to build python
    libraries by pip.
    """
    sudo('apt-get -y -q install python python-dev mercurial git '
        'python-distribute python-pip python-virtualenv')


def _install_postgres():
    """
    Install postgres client packages.

    Install the packages needed to build postgres client utilities via pip.
    The repository for Ubuntu 14.04 (trusty) does not have a new enough version
    to be compatible with the AWS-installed copy of PostgreSQL (9.4.1), so we
    configure the PostgreSQL apt repository and key and *then* do our install.
    """
    run("""echo 'deb http://apt.postgresql.org/pub/repos/apt/ trusty-pgdg main
' | sudo tee -a /etc/apt/sources.list.d/pgdg.list""")
    run('wget -qO - https://www.postgresql.org/media/keys/ACCC4CF8.asc | '
        'sudo apt-key add -')
    sudo('apt-get update')
    sudo('apt-get -y -q install postgresql-common libpq-dev postgresql-client')


@task(alias='sys')
def install_system_packages():
    """
    Install all system packages required for Adage.

    Install all python, postgres, elasticsearch, and other packages required to
    deploy and manage an Adage instance.
    """
    # first, ensure we have latest versions of everything
    sudo('apt-get update')
    sudo('apt-get -y -q upgrade')
    sudo('apt-get -y -q dist-upgrade')
    # now handle specific system packages we need
    execute(_install_elasticsearch)
    execute(_install_python_deps)
    execute(_install_postgres)
    sudo('apt-get -y -q install nodejs-legacy build-essential nginx npm '
        'supervisor')
    sudo('npm -g install grunt-cli karma bower phantomjs-prebuilt')


@task
def setup_elasticsearch():
    """
    Configure ElasticSearch.

    Make a location for the search index, and configure the server to allow
    connections from localhost.
    """
    sudo('mkdir /var/elastic')
    sudo('chown -R elasticsearch:elasticsearch /var/elastic')
    sudo('sysctl -w vm.max_map_count=262144')
    run("echo 'ES_HEAP_SIZE=512m' | sudo tee -a /etc/environment")
    sudo('update-rc.d elasticsearch defaults 95 10')

    # elasticsearch should only look at this host. Create config files.
    # setting network.host per
    #  https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html
    # since we were getting the same discovery errors in our log as
    # HansPeterSloot at this thread <https://groups.google.com/forum/#!msg/elasticsearch/aVeipLZ5s0c/VXgQerDDuRYJ>
    # (requires installation of
    # https://github.com/elastic/elasticsearch-cloud-aws as we have done above)
#     run("""echo 'network.host: _ec2_
# script.disable_dynamic: true
    run("""echo 'script.disable_dynamic: true
bootstrap.mlockall: true
path.data: /var/elastic
path.logs: /var/log/elasticsearch
cluster.name: adagesearch
' | sudo tee -a /etc/elasticsearch/elasticsearch.yml""")
    # note: must have pty=False below for init script to work properly. See:
    # <http://docs.fabfile.org/en/1.6/faq.html>
    sudo('/etc/init.d/elasticsearch restart', pty=False)


@task
def create_adage_user():
    """
    Create an adage user.

    Before running this command, make sure that you have created a file named
    authorized_keys in this directory that contains the public keys for people
    that will need to be able to access this instance of Adage as a user
    "adage".
    """
    logging.info("\nChecking for a non-empty copy of authorized_keys to upload"
        " for access to server...")
    local("test -s authorized_keys")
    sudo('adduser adage --disabled-password --gecos "&"')
    sudo('mkdir /home/adage/.ssh', user="adage")
    sudo('chmod 700 /home/adage/.ssh')
    put('authorized_keys', '/home/adage/.ssh/', use_sudo=True, mode=0600)
    sudo('chown adage:adage /home/adage/.ssh/authorized_keys')


@task
def setup_database():
    """
    Configure default AWS PostgreSQL setup with a login role for this web server
    """
    ## create .pgpass in /home/ubuntu with master db user info
    run("touch /home/ubuntu/.pgpass")
    run("chmod 600 /home/ubuntu/.pgpass")
    run(("echo '{HOST}:{PORT}:{NAME}:{USER}:{PASSWORD}' >> "
        "/home/ubuntu/.pgpass").format(**CONFIG['dbmaster']))
    
    sqlstr = """echo "create role {USER} with login createdb;
alter role {USER} with password '{PASSWORD}' valid until 'infinity';
grant {USER} to {MASTER_USER};
set role {USER};
create database {NAME};
" """.format(MASTER_USER=CONFIG['dbmaster']['USER'], 
        **CONFIG['databases']['default'])
    run(sqlstr + ' | psql --host={HOST} --dbname={NAME} --username={USER}'
        ' --no-password'.format(**CONFIG['dbmaster']))
    
    ## create .pgpass in /home/adage with adage user info
    sudo("touch /home/adage/.pgpass", user="adage")
    sudo("chmod 600 /home/adage/.pgpass", user="adage")
    sudo(("echo '{HOST}:{PORT}:{NAME}:{USER}:{PASSWORD}' >> "
        "/home/adage/.pgpass").format(**CONFIG['databases']['default']),
        user="adage")
    # TODO Test that these additions work as planned
    ## create .pg_service.conf with connection parameters for the adage user
    sudo("touch /home/adage/.pg_service.conf", user="adage")
    sudo("chmod 600 /home/adage/.pg_service.conf", user="adage")
    sudo(("echo -e '[{NAME}]\nhost={HOST}\nport={PORT}\nuser={USER}' >> "
        "/home/adage/.pg_service.conf").format(
            **CONFIG['databases']['default']), user="adage"
    )


def add_deploy_key():
    """
    Add deployment keys.
    
    This command takes the private key referenced in 
    AWS_DEPLOY['deploy']['keyfile'] and uploads it to the server so it can
    access the GitHub repository (which needs to have
    AWS_DEPLOY['deploy']['keyfile_pub'] as a deployment key for this to work).
    """
    put(config.AWS_DEPLOY['deploy']['keyfile'], '/home/adage/.ssh/id_rsa',
        use_sudo=True, mode=0600)
    sudo('chown adage:adage /home/adage/.ssh/id_rsa')


@task
def add_known_hosts():
    """
    This command pre-populates the adage user's .ssh/known_hosts file so we
    are not prompted to add a new key when we access github.com and
    bitbucket.com for the first time
    """
    sudo('ssh-keyscan -t rsa github.com bitbucket.org > '
        '/home/adage/.ssh/known_hosts', user="adage")


def create_deploy_keys():
    """
    Create deployment keys.

    This command will create deployment keys on the remote server and download
    the public key as deploy_rsa.pub. Add this deployment key to bitbucket to
    be able to clone the mercurial repositories.
    """
    # TODO if the deployment key is not present, offer to generate one
    # # new way (generate if needed):
    # local("ssh-keygen -b 8192 -f deploy_rsa -t rsa -N ''")


@task(alias='ca')
def clone_adage_repo():
    """
    Clone the Adage and the greenelab.bitbucket.org repositories.

    This command clones the adage repository from GitHub into
    /home/adage/adage-server and the greenelab.bitbucket.org repository into
    /home/adage/greenelab. The adage repository is the location where the python
    code for the server is stored and the greenelab repository contains extra
    static files to be served outside of the adage application. It also
    downloads *just* the get_pseudo_sdrf.py file from the get_pseudomonas
    repository for bootstrapping.
    """
    sudo('git clone {repo} '.format(**CONFIG) +
        '/home/adage/adage-server', user="adage")
    sudo('hg clone ssh://hg@bitbucket.org/greenelab/greenelab.bitbucket.org '
        '/home/adage/greenelab', user="adage")
    # this method is simpler but requires using a password, so it's 
    # less desirable --> 
    # run('wget -q https://bitbucket.org/greenelab/get_pseudomonas/raw/281f4fe00240e3effb4e5bc9a516e8a3716b9ede/get_pseudo_sdrf.py')
    sudo('hg clone --noupdate https://bitbucket.org/greenelab/get_pseudomonas '
        '/home/adage/temp', user="adage")
    sudo('hg cat /home/adage/temp/get_pseudo_sdrf.py --rev tip '
        '-o "/home/adage/%s"', user="adage")
    sudo('hg cat /home/adage/temp/gen_spreadsheets.py --rev tip '
        '-o "/home/adage/%s"', user="adage")
    sudo('rm -rf /home/adage/temp', user="adage")


@task
def setup_nginx():
    """
    Setup nginx.

    This command will remove the default nginx site, and put a configuration
    file for adage into the sites-enabled folder.
    """
    sudo('rm -f /etc/nginx/sites-enabled/default')
    put('files/nginx/adage-nginx.conf',
        '/etc/nginx/sites-enabled/', use_sudo=True)
    sudo('/etc/init.d/nginx restart')


@task
def tweak_nginx_for_dev():
    """
    Tweak the nginx configuration for use on a development server. In
    production, we turn away requests with no Host header, but this is
    inconvenient for a development server, which may not have a host name.
    """
    sudo("sed -i -e '1,/}/{h;d;};/./,$!d' "
        "-e '/server_name/s/server_name .*;/server_name \"\";/' "
        "/etc/nginx/sites-enabled/adage-nginx.conf")
    sudo('/etc/init.d/nginx restart')


@task
def setup_virtualenv():
    """
    Setup Python Virtual Envrionment.

    This command will create a virtual environment for Adage in
    /home/adage/.virtualenvs. This is the virtualenv that will contain the
    python packages that are pip installed from Adage's requirements.txt
    """
    sudo('mkdir -p /home/adage/.virtualenvs', user='adage')
    sudo('virtualenv /home/adage/.virtualenvs/adage', user='adage')
    # TODO add 'act' alias here
    # alias act='source ~/.virtualenvs/adage/bin/activate'


@task
def setup_supervisor():
    """
    Setup supervisor.

    Supervisor allows us to control gunicorn instances of Adage. gunicorn can
    be installed in the virtualenv, and the "adage" user can restart the server
    without requiring unrestricted sudo.
    """
    put('files/supervisord/adage_super.conf',
        '/etc/supervisor/conf.d/adage_super.conf', use_sudo=True)
    # systemctl now used for services in Ubuntu 16.04
    sudo('systemctl enable supervisor')
    sudo('systemctl start supervisor')


@task
def setup_sudo_restart_super():
    """
    Allow the adage user to restart Supervisor.

    Create a supervisor group, add adage to it, upload a sudo configuration that
    allows the adage user to perform the restart procedure for the adage server.
    """
    put('files/supervisord/super_sudo',
        '/etc/sudoers.d/super_sudo', use_sudo=True, mode=0440)
    sudo('chown root:root /etc/sudoers.d/super_sudo')
    sudo('sudo /etc/init.d/supervisor restart')


@task
def configure_system():
    """
    Configure all base system setup tasks we can do before setting up the
    adage user
    """
    install_system_packages()
    enable_unattended_updates()
    setup_elasticsearch()


@task
def configure_adage():
    """
    Create the adage user and complete all user-dependent configuration
    """
    # create the adage user; make sure authorized_keys has been created
    create_adage_user()
    
    # create a database for this instance
    setup_database()
    
    # add deployment keys for access to source repository
    add_deploy_key()
    add_known_hosts()
    
    # you need to have put the adage deployment key on the bitbucket repo
    # before this step.
    clone_adage_repo()
    
    # you need to have setup the configuration (e.g. correct domain name, etc)
    # for the adage-nginx.conf file before running this step.
    setup_nginx()
    
    # create the virtualenv that adage uses
    setup_virtualenv()
    
    # setup supervisord -- you can configure the parameters for gunicorn but
    # the ones that exist are probably somewhat reasonablish.
    setup_supervisor()
    
    # allow the adage user to have permissions to restart adage (e.g. the
    # gunicorn process) via supervisor.
    setup_sudo_restart_super()


def _deploy(hostlist):
    """
    Execute a complete deployment to provision a new adage server
    (replaces steps.sh)
    """
    logging.info("Deploying to hostlist: [" + ','.join(hostlist) + "]")
    
    execute(configure_system, hosts=hostlist)
    local('date')
    # execute(reboot, hosts=hostlist)
    with settings(warn_only=True):
        print 'rebooting'
        start_time = time.time()
        execute(reboot, wait=1200, hosts=hostlist)
        print 'reboot took: {} seconds'.format(time.time() - start_time)
    local('date')
    print("env.hosts: [" + ', '.join(env.hosts) + "]")
    # run('uname -a')
    execute(configure_adage, hosts=hostlist)

    # now we use the connection info specified in CONFIG['os'] to connect
    # as that user (specify the host first) & then complete deployment
    CONFIG['os']['host'] = hostlist[0].split(r'@')[1]
    print_config()
    execute(adage_server.setup_host_conn, use_conn=CONFIG['os'])
    execute(adage_server.deploy, use_config=CONFIG)


@task
def deploy_aws():
    """
    Launch an EC2 instance using the parameters in config.py and deploy
    to that server when it has spun up.
    """
    global CONFIG
    CONFIG = config.AWS_CONFIG
    execute(launch_ec2_instance)
    # capture the IP address for the host we just launched and build a hostlist
    hostlist = [ 'ubuntu@' + h for h in env.hosts ]
    _deploy(hostlist)


@task
def deploy_dev():
    """
    Set up a connection to the currently-defined host_conn and deploy a
    development configuration to it
    """
    global CONFIG
    CONFIG = config.DEV_CONFIG
    execute(adage_server.setup_host_conn, use_conn=CONFIG['host_conn'])
    _deploy(env.hosts)
    # _deploy switches to a different 'host_conn' so we need to reset here
    execute(adage_server.setup_host_conn, use_conn=CONFIG['host_conn'])
    execute(tweak_nginx_for_dev, hosts=env.hosts)


@task
def dropdb():
    CONFIG = config.AWS_CONFIG
    sqlstr = """echo "drop database {NAME};
drop role {NAME};" """.format(**CONFIG['databases']['default'])
    run(sqlstr + ' | psql --host={HOST} --username={USER}'.format(
        sql=sqlstr, **CONFIG['dbmaster']))


@task(alias='resume')
def resumedeploy():
    # Supply the key and hostlist needed to resume, then
    # insert failed deployment steps to retry them below ---
    # env.key_filename = ['~/.ssh/aws_ubuntu.pem']
    # hostlist=['ubuntu@<aws_public_ip>']
    # ---
    pass
