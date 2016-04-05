#!/bin/bash

set -xe
BASE_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd ../../ && pwd )

cd ${BASE_DIR}/.docker/staging

set +x
if [ "${WEBCRON_TOKEN}" != "" ]; then
  sed -i "s/WEBCRON_TOKEN/${WEBCRON_TOKEN}/" ${BASE_DIR}/.docker/staging/fez.cron
fi
if [ "${APP_ENVIRONMENT}" == "staging" ]; then
  aws s3 cp s3://uql/ecs/default/services/fezstaging/config.inc.php ${BASE_DIR}/public/config.inc.php
  aws s3 cp s3://uql/fez/fez_staging_cloudfront_private_key.pem ${BASE_DIR}/data/
  aws s3 cp ${BASE_DIR}/.docker/staging/fez.cron s3://uql/ecs/default/services/crond/cron.d/fezstaging
  # for the mounts
  aws s3 cp s3://uql/fez/espace.credentials ${BASE_DIR}/data/
  aws s3 cp s3://uql/fez/libtools.credentials ${BASE_DIR}/data/
  aws s3 cp s3://uql/fez/espace.fstab ${BASE_DIR}/data/
  cat ${BASE_DIR}/data/espace.fstab >> /etc/fstab
else
  cp ${BASE_DIR}/.docker/testing/config.inc.php /var/app/current/public/config.inc.php
fi

rm -f /etc/php.d/15-xdebug.ini

if [ "${NEWRELIC_LICENSE}" != "" ]; then
  sed -i "s/NEWRELIC_LICENSE/${NEWRELIC_LICENSE}/" /etc/nginx/conf.d/fez.conf
fi
set -x

if [ "${BGP_ID}" != "" ]; then
  php ${BASE_DIR}/public/misc/run_background_process.php ${BGP_ID}
else
  exec /usr/sbin/php-fpm --nodaemonize
fi
