##Just a small script to get an updatable version of an a+ apache ssl conf

### What you need
apache2.4
openssl < 1.0.2d
certificate(s) from letsencrypt.org

### What it does
#####- generate dh parameters if no present
#####- create a certificate with those dh params
#####- create a fingerprints for public and private key
#####- write an example page conf which you can use

### Where you can test the conf
https://globalsign.ssllabs.com/analyze.html

####Like shown in this tutorial
https://community.letsencrypt.org/t/howto-a-with-all-100-s-on-ssl-labs-test-using-apache2-4-read-warnings/2436