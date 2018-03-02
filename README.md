# shibboleth-idp-oidc-extension

[![Build Status](https://travis-ci.org/CSCfi/shibboleth-idp-oidc-extension.svg?branch=master)](https://travis-ci.org/CSCfi/shibboleth-idp-oidc-extension)

The goal of the project is to provide a [OpenID Connect](http://openid.net/connect/) OP extension to [Shibboleth IdP V3](https://wiki.shibboleth.net/confluence/display/IDP30/Home). The work is done as part of task T3.1A OpenID Connect Federation in GN4-2 JRA3 project.

First alpha release 0.5 has been released that supports imlicit flow. 

Now we are working with code flow and hope to release 0.6a by the end of march.

The Shibboleth IdP 3.3 installed by this project is extended to act as a [OpenID Connect](http://openid.net/connect/) provider for implicit flow.  


## Prerequisites
- Java 7+
- [Apache Maven 3](https://maven.apache.org/)
- [Vagrant](https://www.vagrantup.com/)

## Deployment
The maven project needs to be built first. The ansible scipts will then perform first installation of Shibboleth Idp V3, after which the extensions are installed. 

```

git clone https://github.com/CSCfi/shibboleth-idp-oidc-extension
cd shibboleth-idp-oidc-extension/idp-oidc-extension-parent/
mvn package
cd ..
vagrant up

```

## Playing around

### Login
You need to be root to access all the necessary files. 
```
vagrant ssh
sudo su -
```

### View logs
By following log entries it should be possible to get an idea of the execution.
```
tail -f /opt/shibboleth-idp/logs/idp-process.log
``` 

#### LDAP User to authenticate with
The LDAP user is Ted Tester, in Finnish:

```
user:teppo
password:testaaja
```

### Configuration
See wiki

