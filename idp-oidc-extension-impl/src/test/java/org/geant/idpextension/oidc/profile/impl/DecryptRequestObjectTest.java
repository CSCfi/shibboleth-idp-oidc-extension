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

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.security.impl.OIDCDecryptionParameters;
import org.geant.security.jwk.BasicJWKCredential;
import org.opensaml.messaging.context.BaseContext;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.profile.context.EncryptionContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import junit.framework.Assert;

/** {@link DecryptRequestObject} unit test. */
public class DecryptRequestObjectTest {

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    private DecryptRequestObject action;

    private RequestContext requestCtx;

    private OIDCMetadataContext oidcCtx;

    private OIDCAuthenticationResponseContext oidcRespCtx;

    private KeyPair kp;

    @BeforeMethod
    public void setup() throws ComponentInitializationException, NoSuchAlgorithmException {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        oidcCtx = prc.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        oidcRespCtx = new OIDCAuthenticationResponseContext();
        prc.getOutboundMessageContext().addSubcontext(oidcRespCtx);
        OIDCClientMetadata metaData = new OIDCClientMetadata();
        OIDCClientInformation information = new OIDCClientInformation(new ClientID("test"), null, metaData,
                new Secret("ultimatetopsecretultimatetopsecret"), null, null);
        oidcCtx.setClientInformation(information);
        BaseContext ctx = prc.getSubcontext(RelyingPartyContext.class, true);
        EncryptionContext encCtx = (EncryptionContext) ctx.getSubcontext(EncryptionContext.class, true);
        OIDCDecryptionParameters params = new OIDCDecryptionParameters();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kp = kpg.generateKeyPair();
        BasicJWKCredential credentialRSA = new BasicJWKCredential();
        credentialRSA.setPrivateKey(kp.getPrivate());
        params.getKeyTransportDecryptionCredentials().add(credentialRSA);
        kp = kpg.generateKeyPair();
        BasicJWKCredential credentialRSA2 = new BasicJWKCredential();
        credentialRSA2.setPrivateKey(kp.getPrivate());
        params.getKeyTransportDecryptionCredentials().add(credentialRSA2);
        params.setKeyTransportEncryptionAlgorithm("RSA-OAEP-256");
        params.setDataEncryptionAlgorithm("A128CBC-HS256");
        encCtx.setAttributeEncryptionParameters(params);
        action = new DecryptRequestObject();
        action.initialize();
    }

    /**
     * Test success in case of not having request object
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testSuccessNoObject()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test success in case of not having to decrypt.
     * @throws ParseException 
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testSuccessNotJWE()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException, ParseException {
        JWTClaimsSet ro = new JWTClaimsSet.Builder().subject("alice").build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).requestObject(new PlainJWT(ro))
                        .state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals("alice",oidcRespCtx.getRequestObject().getJWTClaimsSet().getSubject());
    }

    @SuppressWarnings("unchecked")
    private void setObject(JWEAlgorithm alg, EncryptionMethod enc) throws JOSEException, ParseException {
        PlainJWT plainJWT = new PlainJWT(new JWTClaimsSet.Builder().subject("alice").build());
        JWEObject jweObject = new JWEObject(new JWEHeader.Builder(alg, enc).contentType("JWT").build(),
                new Payload(plainJWT.serialize()));
        jweObject.encrypt(new RSAEncrypter((RSAPublicKey) kp.getPublic()));
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback"))
                        .requestObject(EncryptedJWT.parse(jweObject.serialize())).state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
    }

    /**
     * Test decrypt success.
     */
    @Test
    public void testRequestObjectDecryptSuccess() throws NoSuchAlgorithmException, ComponentInitializationException,
            URISyntaxException, JOSEException, ParseException {
        setObject(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertEquals("alice",oidcRespCtx.getRequestObject().getJWTClaimsSet().getSubject());
    }

    /**
     * Test decrypt failure, no matching key.
     */
    @Test
    public void testRequestObjectDecryptFailureNoMatchingKey() throws NoSuchAlgorithmException,
            ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kp = kpg.generateKeyPair();
        setObject(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_REQUEST_OBJECT);
    }

    /**
     * Test decrypt failure, kt alg not matching.
     */
    @SuppressWarnings("deprecation")
    @Test
    public void testRequestObjectDecryptFailureNoMatchingAlg() throws NoSuchAlgorithmException,
            ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        setObject(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_REQUEST_OBJECT);
    }

    /**
     * Test decrypt failure, enc alg not matching.
     */
    @Test
    public void testRequestObjectDecryptFailureNoMatchingEnc() throws NoSuchAlgorithmException,
            ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        setObject(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_REQUEST_OBJECT);
    }

    /**
     * Test decrypt failure, no params.
     */
    @Test
    public void testRequestObjectFailureNoParameters() throws NoSuchAlgorithmException,
            ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        prc.getSubcontext(RelyingPartyContext.class, false).getSubcontext(EncryptionContext.class, false)
                .setAttributeEncryptionParameters(null);
        setObject(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_SEC_CFG);
    }

    /**
     * Test decrypt failure, no enc context.
     */
    @Test
    public void testRequestObjectFailureNoEncCtx() throws NoSuchAlgorithmException, ComponentInitializationException,
            URISyntaxException, JOSEException, ParseException {
        prc.getSubcontext(RelyingPartyContext.class, false).removeSubcontext(EncryptionContext.class);
        setObject(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_SEC_CFG);
    }

}