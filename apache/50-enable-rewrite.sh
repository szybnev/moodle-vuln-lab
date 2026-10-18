#!/bin/sh
# Sourced by the moodlehq/moodle-php-apache entrypoint before Apache starts.
# hardened.conf uses mod_rewrite, which the image does not enable by default.
a2enmod rewrite >/dev/null
