##Just a small script to get an updatable version of an a+ apache ssl conf

![Alt text](https://raw.githubusercontent.com/mommel/letsencrypt-aplus/master/aplussign.png)

### What to do
Just put the sh file on your server and run it
./ssl2aplus.sh

-
### Download
[ssl2aplus.sh](https://raw.githubusercontent.com/mommel/letsencrypt-aplus/master/ssl2aplus.sh "ssl2aplus.sh")

-
### What you need
* apache2.4 or Nginx
* openssl < 1.0.2d (Apache)
* certificate(s) from letsencrypt.org

-
### What it does
* generate dh parameters if no present
* create a certificate with those dh params (for Apache with openssl < 1.0.2d
* create a fingerprints for public and private key
* write an example page conf which you can use

-
### Where you can test the conf
https://globalsign.ssllabs.com/analyze.html

-
####Like shown in this tutorial
https://community.letsencrypt.org/t/howto-a-with-all-100-s-on-ssl-labs-test-using-apache2-4-read-warnings/2436

-
####Just for experimental usage, if you want to use it in prod systems verify all settings for yourself
