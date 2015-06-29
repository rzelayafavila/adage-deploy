# setup unattended updates
fab -H <aws-dns> -u ubuntu -i <key.pem> enable_unattended_updates

# install packages
fab -H <aws-dns> -u ubuntu -i <key.pem> install_system_packages

# configure elasticsearch
fab -H <aws-dns> -u ubuntu -i <key.pem> setup_elasticsearch

# create the adage user; make sure authorized_keys has been created by this point.
fab -H <aws-dns> -u ubuntu -i <key.pem> create_adage_user

# create the deployment key and retrieve it -- be prepared to enter a password for your ssh key
# also let it save to the default location -- we count on that for the download.
fab -H <aws-dns> -u ubuntu -i <key.pem> create_deploy_keys

# you need to have put the adage deployment key on the bitbucket repo before this step.
fab -H <aws-dns> -u ubuntu -i <key.pem> clone_adage_repo

# you need to have setup the configuration (e.g. correct domain name, etc) for the
# adage-nginx.conf file before running this step.
fab -H <aws-dns> -u ubuntu -i <key.pem> setup_nginx

# create the virtualenv that adage uses
fab -H <aws-dns> -u ubuntu -i <key.pem> setup_virtualenv

# setup supervisord -- you can configure the parameters for gunicorn but the ones that
# exist are probably somewhat reasonablish.
fab -H <aws-dns> -u ubuntu -i <key.pem> setup_supervisor

# allow the adage user to have permissions to restart adage (e.g. the gunicorn process)
# via supervisor. If you want to configure 
fab -H <aws-dns> -u ubuntu -i <key.pem> setup_sudo_restart_super

