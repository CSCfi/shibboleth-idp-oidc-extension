/*
 * Copyright (c) 2017 - 2020, GÉANT
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.geant.idpextension.oidc.profile.impl;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.annotation.Nonnull;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.BasicKeystoreKeyStrategy;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;
import org.geant.idpextension.oidc.config.OIDCCoreProtocolConfiguration;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.spring.factory.BasicJWKCredentialFactoryBean;
import org.geant.idpextension.oidc.storage.RevocationCache;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.credential.Credential;
import org.springframework.core.io.ClassPathResource;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.ext.spring.resource.ResourceHelper;
import net.shibboleth.idp.profile.RequestContextBuilder;

/** base class for tests expecting to have inbound and outbound msg ctxs etc in place. */
public abstract class BaseOIDCResponseActionTest {

    protected RequestContext requestCtx;

    protected OIDCAuthenticationResponseContext respCtx;

    protected OIDCMetadataContext metadataCtx;

    protected AuthenticationRequest request;

    protected RelyingPartyContext rpCtx;

    final protected String subject = "generatedSubject";

    final protected String clientId = "s6BhdRkqt3";

    private DataSealer dataSealer;

    protected IdentifierGenerationStrategy idGenerator = new SecureRandomIdentifierGenerationStrategy();

    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext profileRequestCtx;

    Credential credentialRSA;

    Credential credentialEC256;

    Credential credentialEC384;

    Credential credentialEC521;

    Credential credentialHMAC;

    public BaseOIDCResponseActionTest() {
        try {
            BasicJWKCredentialFactoryBean factory = new BasicJWKCredentialFactoryBean();
            factory.setJWKResource(new ClassPathResource("credentials/idp-signing-es.jwk"));
            factory.afterPropertiesSet();
            credentialEC256 = factory.getObject();

            factory = new BasicJWKCredentialFactoryBean();
            factory.setJWKResource(new ClassPathResource("credentials/idp-signing-es384.jwk"));
            factory.afterPropertiesSet();
            credentialEC384 = factory.getObject();

            factory = new BasicJWKCredentialFactoryBean();
            factory.setJWKResource(new ClassPathResource("credentials/idp-signing-es521.jwk"));
            factory.afterPropertiesSet();
            credentialEC521 = factory.getObject();

            factory = new BasicJWKCredentialFactoryBean();
            factory.setJWKResource(new ClassPathResource("credentials/idp-signing-rs.jwk"));
            factory.afterPropertiesSet();
            credentialRSA = factory.getObject();

            factory = new BasicJWKCredentialFactoryBean();
            factory.setJWKResource(new ClassPathResource("credentials/idp-signing-dir.jwk"));
            factory.afterPropertiesSet();
            credentialHMAC = factory.getObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Default setup.
     * 
     * @throws Exception
     */
    @SuppressWarnings({"unchecked"})
    @BeforeMethod
    protected void setUp() throws Exception {
        request = AuthenticationRequest.parse(
                "response_type=id_token+token&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20email%20profile%20offline_access&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
        requestCtx = new RequestContextBuilder().setInboundMessage(request).buildRequestContext();
        final MessageContext<AuthenticationResponse> msgCtx = new MessageContext<AuthenticationResponse>();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        profileRequestCtx.setOutboundMessageContext(msgCtx);
        respCtx = new OIDCAuthenticationResponseContext();
        profileRequestCtx.getOutboundMessageContext().addSubcontext(respCtx);
        metadataCtx = (OIDCMetadataContext) profileRequestCtx.getInboundMessageContext()
                .addSubcontext(new OIDCMetadataContext());
        OIDCClientInformation information =
                new OIDCClientInformation(new ClientID(clientId), new Date(), new OIDCClientMetadata(), new Secret());
        metadataCtx.setClientInformation(information);
        rpCtx = profileRequestCtx.getSubcontext(RelyingPartyContext.class, true);
        rpCtx.setRelyingPartyId(clientId);
        respCtx.setSubject(subject);
        rpCtx.setProfileConfig(new OIDCCoreProtocolConfiguration());
    }

    @SuppressWarnings("unchecked")
    protected void setAuthenticationRequest(AuthenticationRequest req) {
        profileRequestCtx.getInboundMessageContext().setMessage(req);
    }

    @SuppressWarnings("unchecked")
    protected void setTokenRequest(TokenRequest req) {
        profileRequestCtx.getInboundMessageContext().setMessage(req);
    }

    @SuppressWarnings("unchecked")
    protected void setUserInfoRequest(UserInfoRequest req) {
        profileRequestCtx.getInboundMessageContext().setMessage(req);
    }

    protected void setIdTokenToResponseContext(String iss, String sub, String aud, Date exp, Date iat) {
        List<Audience> audience = new ArrayList<Audience>();
        audience.add(new Audience(aud));
        IDTokenClaimsSet idToken = new IDTokenClaimsSet(new Issuer(iss), new Subject(sub), audience, exp, iat);
        respCtx.setIDToken(idToken);
    }

    protected void signIdTokenInResponseContext() throws ParseException, JOSEException {
        SignedJWT jwt = null;
        jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("id").build(),
                respCtx.getIDToken().toJWTClaimsSet());
        jwt.sign(new RSASSASigner(credentialRSA.getPrivateKey()));
        respCtx.setProcessedToken(jwt);
    }

    protected void setUserInfoResponseToResponseContext(String sub) {
        UserInfo info = new UserInfo(new Subject(sub));
        respCtx.setUserInfo(info);
    }

    protected void signUserInfoResponseInResponseContext() throws ParseException, JOSEException {
        SignedJWT jwt = null;
        jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("id").build(),
                respCtx.getUserInfo().toJWTClaimsSet());
        jwt.sign(new RSASSASigner(credentialRSA.getPrivateKey()));
        respCtx.setProcessedToken(jwt);
    }

    protected DataSealer getDataSealer() throws ComponentInitializationException, NoSuchAlgorithmException {
        if (dataSealer == null) {
            dataSealer = initializeDataSealer();
        }
        return dataSealer;
    }
    
    public static DataSealer initializeDataSealer() throws ComponentInitializationException, NoSuchAlgorithmException {
        final BasicKeystoreKeyStrategy strategy = new BasicKeystoreKeyStrategy();
        strategy.setKeystoreResource(ResourceHelper.of(new ClassPathResource("credentials/sealer.jks")));
        strategy.setKeyVersionResource(ResourceHelper.of(new ClassPathResource("credentials/sealer.kver")));
        strategy.setKeystorePassword("password");
        strategy.setKeyAlias("secret");
        strategy.setKeyPassword("password");
        strategy.initialize();
        final DataSealer dataSealer = new DataSealer();
        dataSealer.setKeyStrategy(strategy);
        dataSealer.setRandom(SecureRandom.getInstance("SHA1PRNG"));
        dataSealer.initialize();
        return dataSealer;
        
    }

    public class MockRevocationCache extends RevocationCache {

        boolean revoke;

        boolean isRevoked;

        MockRevocationCache(boolean revocationQueryOutcome, boolean revokeActionStatus) {
            revoke = revokeActionStatus;
            isRevoked = revocationQueryOutcome;
        }

        @Override
        public void doInitialize() throws ComponentInitializationException {
        }

        @Override
        public synchronized boolean revoke(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String s) {
            return revoke;
        }

        @Override
        public synchronized boolean isRevoked(@Nonnull @NotEmpty final String context,
                @Nonnull @NotEmpty final String s) {
            return isRevoked;
        }

    }

}