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

import net.minidev.json.JSONObject;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.UnmodifiableComponentException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.security.jwk.BasicJWKCredential;
import org.opensaml.messaging.context.BaseContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.profile.context.EncryptionContext;
import org.opensaml.xmlsec.EncryptionParameters;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.base.Functions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import junit.framework.Assert;

/** {@link EncryptProcessedToken} unit test. */
public class EncryptProcessedTokenTest {

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    private EncryptProcessedToken action;

    private RequestContext requestCtx;

    private OIDCMetadataContext oidcCtx;

    private OIDCAuthenticationResponseContext oidcRespCtx;

    private KeyPair kp;

    private EncryptionContext encCtx;

    @SuppressWarnings("unchecked")
    @BeforeMethod
    public void setup() throws ComponentInitializationException, NoSuchAlgorithmException, JOSEException {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcCtx = prc.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        oidcRespCtx = new OIDCAuthenticationResponseContext();
        prc.getOutboundMessageContext().addSubcontext(oidcRespCtx);
        OIDCClientMetadata metaData = new OIDCClientMetadata();
        OIDCClientInformation information = new OIDCClientInformation(new ClientID("test"), null, metaData,
                new Secret("ultimatetopsecretultimatetopsecret"), null, null);
        oidcCtx.setClientInformation(information);
        BaseContext ctx = prc.getSubcontext(RelyingPartyContext.class, true);
        encCtx = (EncryptionContext) ctx.getSubcontext(EncryptionContext.class, true);
        EncryptionParameters params = new EncryptionParameters();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kp = kpg.generateKeyPair();
        BasicJWKCredential credentialRSA = new BasicJWKCredential();
        credentialRSA.setPublicKey(kp.getPublic());
        credentialRSA.setKid("myKid");
        params.setKeyTransportEncryptionCredential(credentialRSA);
        params.setKeyTransportEncryptionAlgorithm("RSA-OAEP-256");
        params.setDataEncryptionAlgorithm("A128CBC-HS256");
        encCtx.setAssertionEncryptionParameters(params);
        JWSSigner signer = new RSASSASigner(kp.getPrivate());
        SignedJWT signed =
                new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), new JWTClaimsSet.Builder().subject("alice").build());
        signed.sign(signer);
        oidcRespCtx.setProcessedToken(signed);
        action = new EncryptProcessedToken();
        action.initialize();
    }

    /**
     * Test success basic case. Encrypts ProcessedToken.
     */
    @Test
    public void testSuccess() {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(oidcRespCtx.getProcessedToken() instanceof EncryptedJWT);
        EncryptedJWT jwe = (EncryptedJWT) oidcRespCtx.getProcessedToken();
        Assert.assertEquals("myKid", jwe.getHeader().getKeyID());

    }

    /**
     * Test success case of encrypting unsigned userinfo.
     */
    @Test
    public void testSuccessUserInfo() {
        oidcRespCtx.setProcessedToken(null);
        JSONObject info = new JSONObject();
        info.put("sub", "alice");
        oidcRespCtx.setUserInfo(new UserInfo(info));
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(oidcRespCtx.getProcessedToken() instanceof EncryptedJWT);
    }

    /**
     * Test success basic case using EC. Encrypts ProcessedToken.
     * 
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSuccessEC() throws NoSuchAlgorithmException {
        EncryptionParameters params = new EncryptionParameters();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        kp = kpg.generateKeyPair();
        BasicJWKCredential credentialEC = new BasicJWKCredential();
        credentialEC.setPublicKey(kp.getPublic());
        params.setKeyTransportEncryptionCredential(credentialEC);
        params.setKeyTransportEncryptionAlgorithm("ECDH-ES");
        params.setDataEncryptionAlgorithm("A128CBC-HS256");
        encCtx.setAssertionEncryptionParameters(params);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(oidcRespCtx.getProcessedToken() instanceof EncryptedJWT);
    }

    /**
     * Test fail case of nothing to encrypt.
     */
    @Test
    public void testFailNoInput() {
        oidcRespCtx.setProcessedToken(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.UNABLE_TO_ENCRYPT);
    }

    /**
     * Test case of missing encryption context.
     */
    @Test
    public void testFailNoEncryptionContext() {
        prc.getSubcontext(RelyingPartyContext.class, false).removeSubcontext(EncryptionContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * Test case of missing encryption parameters. Should do nothing.
     */
    @Test
    public void testSuccessNoEnc() throws ParseException {
        prc.getSubcontext(RelyingPartyContext.class, false).getSubcontext(EncryptionContext.class, false)
                .setAssertionEncryptionParameters(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals("alice", oidcRespCtx.getProcessedToken().getJWTClaimsSet().getSubject());
    }

    /**
     * Strategy cannot be set after initialization
     */
    @SuppressWarnings("rawtypes")
    @Test(expectedExceptions = UnmodifiableComponentException.class)
    public void testInitializationFail() {
        action.setEncryptionContextLookupStrategy(
                Functions.compose(new ChildContextLookup<>(EncryptionContext.class, false),
                        new ChildContextLookup<ProfileRequestContext, RelyingPartyContext>(RelyingPartyContext.class)));
    }

    /**
     * Strategy cannot be null
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testInitializationFail2() {
        action = new EncryptProcessedToken();
        action.setEncryptionContextLookupStrategy(null);
    }

}