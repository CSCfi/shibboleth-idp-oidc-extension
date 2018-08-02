/*
 * GÉANT BSD Software License
 *
 * Copyright (c) 2017 - 2020, GÉANT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the GÉANT nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Disclaimer:
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.geant.idpextension.oidc.profile.impl;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.BasicKeystoreKeyStrategy;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;

import org.geant.idpextension.oidc.config.OIDCCoreProtocolConfiguration;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContextSet;
import org.opensaml.security.credential.UsageType;
import org.springframework.core.io.ClassPathResource;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import net.shibboleth.ext.spring.resource.ResourceHelper;
import net.shibboleth.idp.profile.RequestContextBuilder;

/** base class for tests expecting to have inbound and outbound msg ctxs etc in place. */
abstract class BaseOIDCResponseActionTest {

    protected RequestContext requestCtx;

    protected OIDCAuthenticationResponseContext respCtx;

    protected OIDCMetadataContext metadataCtx;

    protected AuthenticationRequest request;

    final protected String subject = "generatedSubject";

    final protected String clientId = "s6BhdRkqt3";

    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext profileRequestCtx;

    Credential credentialRSA = new BaseOIDCResponseActionTest.mockCredential("RSA");

    Credential credentialEC256 = new BaseOIDCResponseActionTest.mockCredential("EC256");

    Credential credentialEC384 = new BaseOIDCResponseActionTest.mockCredential("EC384");

    Credential credentialEC512 = new BaseOIDCResponseActionTest.mockCredential("EC512");

    Credential credentialHMAC = new BaseOIDCResponseActionTest.mockCredential("HMAC");

    /**
     * Default setup.
     * 
     * @throws Exception
     */
    @SuppressWarnings({"unchecked"})
    @BeforeMethod
    protected void setUp() throws Exception {
        request = AuthenticationRequest.parse(
                "response_type=id_token+token&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
        requestCtx = new RequestContextBuilder().setInboundMessage(request).buildRequestContext();
        final MessageContext<AuthenticationResponse> msgCtx = new MessageContext<AuthenticationResponse>();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        profileRequestCtx.setOutboundMessageContext(msgCtx);
        respCtx = new OIDCAuthenticationResponseContext();
        profileRequestCtx.getOutboundMessageContext().addSubcontext(respCtx);
        metadataCtx = (OIDCMetadataContext) profileRequestCtx.getInboundMessageContext()
                .addSubcontext(new OIDCMetadataContext());
        RelyingPartyContext rpCtx = profileRequestCtx.getSubcontext(RelyingPartyContext.class, true);
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
        respCtx.setSignedToken(jwt);

    }

    protected DataSealer getDataSealer() throws ComponentInitializationException, NoSuchAlgorithmException {
        final BasicKeystoreKeyStrategy strategy = new BasicKeystoreKeyStrategy();
        strategy.setKeystoreResource(ResourceHelper.of(new ClassPathResource("credentials/sealer.jks")));
        strategy.setKeyVersionResource(ResourceHelper.of(new ClassPathResource("credentials/sealer.kver")));
        strategy.setKeystorePassword("password");
        strategy.setKeyAlias("secret");
        strategy.setKeyPassword("password");
        strategy.initialize();
        final DataSealer sealer = new DataSealer();
        sealer.setKeyStrategy(strategy);
        sealer.setRandom(SecureRandom.getInstance("SHA1PRNG"));
        sealer.initialize();
        return sealer;
    }

    public class mockCredential implements Credential {

        PrivateKey priv;

        PublicKey pub;

        SecretKey sec;

        mockCredential(String algo) {
            try {
                if ("RSA".equals(algo)) {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                    KeyPair pair = keyGen.generateKeyPair();
                    priv = pair.getPrivate();
                    pub = pair.getPublic();
                } else if ("EC256".equals(algo)) {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
                    keyGen.initialize(Curve.P_256.toECParameterSpec());
                    KeyPair pair = keyGen.generateKeyPair();
                    priv = pair.getPrivate();
                    pub = pair.getPublic();

                } else if ("EC384".equals(algo)) {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
                    keyGen.initialize(Curve.P_384.toECParameterSpec());
                    KeyPair pair = keyGen.generateKeyPair();
                    priv = pair.getPrivate();
                    pub = pair.getPublic();

                } else if ("EC512".equals(algo)) {
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
                    keyGen.initialize(Curve.P_521.toECParameterSpec());
                    KeyPair pair = keyGen.generateKeyPair();
                    priv = pair.getPrivate();
                    pub = pair.getPublic();

                } else {
                    sec = KeyGenerator.getInstance("HmacSha512").generateKey();
                }
            } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        @Override
        public CredentialContextSet getCredentialContextSet() {
            return null;
        }

        @Override
        public Class<? extends Credential> getCredentialType() {
            return null;
        }

        @Override
        public String getEntityId() {
            return null;
        }

        @Override
        public Collection<String> getKeyNames() {
            return null;
        }

        @Override
        public PrivateKey getPrivateKey() {
            return priv;
        }

        @Override
        public PublicKey getPublicKey() {
            return pub;
        }

        @Override
        public SecretKey getSecretKey() {
            return sec;
        }

        @Override
        public UsageType getUsageType() {
            return null;
        }

    }

    public class idStrat implements IdentifierGenerationStrategy {

        @Override
        public String generateIdentifier() {
            return "identifier";
        }

        @Override
        public String generateIdentifier(boolean xmlSafe) {
            return "identifier";
        }

    }

}