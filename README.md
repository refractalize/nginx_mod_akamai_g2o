# Akamai G2O module for Nginx

Controls access to content from Akamai edge servers, using the G2O headers: `X-Akamai-G2O-Auth-Data` and `X-Akamai-G2O-Auth-Sign`.

## Installation

Like any other nginx module use the `--add-module` option when configuring:

    ./configure --add-module=$PATH_TO_G2O_DIR

It requires OpenSSL.

## Configuration

Place the following settings (`g2o`, `g2o_nonce` and `g2o_key`) into a main, server or location section of your conf file:

    location /download {
        g2o        on;
        g2o_nonce  "token";
        g2o_key    "a_password";
    }
