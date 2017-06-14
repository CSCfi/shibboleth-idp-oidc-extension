# shibboleth-idp-oidc-extension
The goal of the project is to introduce a [OpenID Connect](http://openid.net/connect/) OP extension to [Shibboleth IdP V3](https://wiki.shibboleth.net/confluence/display/IDP30/Home). The work is done as part of task T3.1A OpenID Connect Federation in GN4-2 JRA3 project.

## Status 14.6.2017
The development has only gone through it's initial phases and the products may be used only for demonstrational purposes. 

This far the primary goal has been on understanding how [Nimbus library](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk) should be integrated with [Shibboleth IdP V3](https://wiki.shibboleth.net/confluence/display/IDP30/Home) and no effort has yet been made on areas beyond that.

The Shibboleth IdP installed by this project is able to act as a *noncompliant* [OpenID Connect](http://openid.net/connect/) OP when using implicit flow. For instance the ID Token is not signed yet so we are still missing major bits. To achieve compliance is propably part of the next development cycles. 


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

### Initiate authentication
There are few static links available in https://192.168.0.150/static/. Please not the page itself is not informative of the outcome, all the action needs to be followed from the log file. 

### Configuration
You may configure following sections to alter the behaviour.


#### Authentication
Accustomed shibboleth authentication applies. The installed setup has authentication class reference values for OIDC.  
```

```
Only OIDC specific values may be returned in the response or used in the selection of the flow. The OIDC request parameters *prompt*, *max_age* and *acr* have impact on authentication flow selection process.

#### Attributes
Accustomed shibboleth attribute resolver and filtering applies. The installed setup has own OIDC encoder, see the snippet
```

```
Attributes that do not have OIDC encoder are not included in claims even if they were released by filter.

The filter is configured to releases attributes for the "demo_rp". The "demo_rp" is the OIDC Client ID of the configured client in this case.
```

```

#### Metadata
For the rp to be trusted it has to be found in metadata. The metadata in this configuration is found from
```
```
There has to be a redirect uri listed for the rp that matches the redirect uri in the authentication request for the OP to respond. The currently used format for rp metadata is the format used in dynamic client registration.

#### Issuer
As the issuer value we use the EntityID value that can be set in idp.properties.

#### Relying party configuration
OIDC is not a default protocol in this configuration. OIDC is specifically set for "demo_rp". Note this if you add more rp's.
```
```
