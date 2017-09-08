# shibboleth-idp-oidc-extension
The goal of the project is to provide a [OpenID Connect](http://openid.net/connect/) OP extension to [Shibboleth IdP V3](https://wiki.shibboleth.net/confluence/display/IDP30/Home). The work is done as part of task T3.1A OpenID Connect Federation in GN4-2 JRA3 project.

## Status 14.6.2017
The development has only gone through it's initial phases and the products may be used only for demonstrational purposes. 

This far the primary goal has been on understanding how [Nimbus library](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk) should be integrated with [Shibboleth IdP V3](https://wiki.shibboleth.net/confluence/display/IDP30/Home) and no effort has yet been made on areas beyond that.

The Shibboleth IdP installed by this project is able to act as a *noncompliant* [OpenID Connect](http://openid.net/connect/) OP when using implicit flow. The flow will run through success case and perform pretty much the tasks expected from it but for instance (only to name *one* major deficit) the ID Token is not signed yet nor does it handle errors yet as it should.  


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
There are few static links available in https://192.168.0.150/.
```
Authentication request
Authentication request: code flow (unsupported)
Authentication request: max_age=0 / forceAuthn
Authentication request: prompt=none / isPassive
Authentication request: wrong redirect uri
Authentication request: unknown client id
Authentication request, acr=password
Authentication request, acr=notsupported
```
Please note the page itself is not informative of the outcome, all the action needs to be followed from the log file. 

#### LDAP User to authenticate with
The LDAP user is Ted Tester, in Finnish:

```
user:teppo
password:testaaja
```

### Configuration
You may configure following sections to alter the behaviour.


#### Authentication
Accustomed shibboleth authentication applies. The installed setup has authentication class reference values for OIDC.
  
*/opt/shibboleth-idp/conf/authn/general-authn.xml*
```


        <bean id="authn/Password" parent="shibboleth.AuthenticationFlow"
                p:passiveAuthenticationSupported="true"
                p:forcedAuthenticationSupported="true" >
        <property name="supportedPrincipals">
            <list>
              <bean parent="shibboleth.SAML2AuthnContextClassRef"
                  c:classRef="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" />
              <bean parent="shibboleth.SAML2AuthnContextClassRef"
                  c:classRef="urn:oasis:names:tc:SAML:2.0:ac:classes:Password" />
              <bean parent="shibboleth.SAML1AuthenticationMethod"
                  c:method="urn:oasis:names:tc:SAML:1.0:am:password" />
           
              <!-- OIDC authentication context class reference value added -->
              <bean parent="shibboleth.OIDCAuthnContextClassReference"
                  c:classRef="password" />
                  
            </list>
          </property>
        </bean>

```
Only OIDC specific values may be returned in the response or used in the selection of the flow. The weighted map is of course supported also in oidc case. The OIDC request parameters *prompt*, *max_age* and *acr* have impact on authentication flow selection process.

#### Attributes
Accustomed shibboleth attribute resolver and filtering applies. The installed setup has own OIDC encoder, see the snippet:

*/opt/shibboleth-idp/conf/attribute-resolver.xml*
```
    <AttributeDefinition id="mail" xsi:type="Template">
        <Dependency ref="uid" />
        <AttributeEncoder xsi:type="SAML1String" name="urn:mace:dir:attribute-def:mail" encodeType="false" />
        <AttributeEncoder xsi:type="SAML2String" name="urn:oid:0.9.2342.19200300.100.1.3" friendlyName="mail" encodeType="false" />

        <!-- OIDC encoder added -->        
        <AttributeEncoder xsi:type="oidcext:OIDCString" name="mail"/>
        
        <Template>
          <![CDATA[
               ${uid}@example.org
          ]]>
        </Template>
        <SourceAttribute>uid</SourceAttribute>
    </AttributeDefinition>

```
Attributes that do not have OIDC encoder are not included in claims even if they were released by filter.

The filter is configured to releases attributes for the "demo_rp". The "demo_rp" is the OIDC Client ID of the configured client in this case.

*/opt/shibboleth-idp/conf/attribute-filter.xml*

```
<AttributeFilterPolicy id="demo_rp">
    <PolicyRequirementRule xsi:type="Requester" value="demo_rp" />
    ... 
```

#### Metadata
For the rp to be trusted it has to be found in metadata. The metadata in this configuration is found from

/opt/shibboleth-idp/metadata/oidc-client.json 
```
{"id":{"value":"demo_rp"},"issueDate":"Apr 24, 2017 1:20:56 PM","metadata":{"redirectURIs":["https://192.168.0.150/static"],"nameEntries":{},"logoURIEntries":{},"uriEntries":{},"policyURIEntries":{},"tosURIEntries":{},"customFields":{}},"secret":{"value":[115,101,99,114,101,116]}}

```
There has to be a redirect uri listed for the rp that matches the redirect uri in the authentication request for the OP to respond. The currently used format for rp metadata is the format used in dynamic client registration.

#### Issuer
As the issuer value we use the EntityID value that can be set in idp.properties.

#### Relying party configuration
OIDC is not a default profile in this configuration. OIDC profile configuration is specifically set for "demo_rp". Note this if you add more rp's.

*/opt/shibboleth-idp/conf/relying-party.xml*
```
<bean parent="RelyingPartyByName" c:relyingPartyIds="demo_rp">
     <property name="profileConfigurations">
          <list>
              <!-- OIDC protocol support -->
              <bean parent="OIDC.SSO" p:postAuthenticationFlows="attribute-release" />
          </list>
      </property>
</bean>

```
