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
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.security.impl.OIDCSignatureValidationParameters;
import org.geant.security.jwk.BasicJWKCredential;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/** {@link ValidateRequestObject} unit test. */
public class ValidateRequestObjectTest {

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;

    private ValidateRequestObject action;

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
        SecurityParametersContext secCtx =
                (SecurityParametersContext) prc.addSubcontext(new SecurityParametersContext());
        OIDCSignatureValidationParameters params = new OIDCSignatureValidationParameters();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kp = kpg.generateKeyPair();
        BasicJWKCredential credentialRSA = new BasicJWKCredential();
        credentialRSA.setAlgorithm(JWSAlgorithm.parse("RS256"));
        credentialRSA.setPublicKey(kp.getPublic());
        params.getValidationCredentials().add(credentialRSA);
        kp = kpg.generateKeyPair();
        BasicJWKCredential credentialRSA2 = new BasicJWKCredential();
        credentialRSA2.setAlgorithm(JWSAlgorithm.parse("RS256"));
        credentialRSA2.setPublicKey(kp.getPublic());
        params.getValidationCredentials().add(credentialRSA2);
        params.setSignatureAlgorithm("RS256");
        secCtx.setSignatureSigningParameters(params);
        action = new ValidateRequestObject();
        action.initialize();
    }

    /**
     * Test that success in case of not having request object
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
     * Test success in case of having non signed request object and no registered algorithm
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectNoMatchingClaims()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        JWTClaimsSet ro = new JWTClaimsSet.Builder().subject("alice").build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).requestObject(new PlainJWT(ro))
                        .state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test failure case of having non signed request object and registered algorithm other than 'none'
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectAlgMismatch()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        oidcCtx.getClientInformation().getOIDCMetadata().setRequestObjectJWSAlg(JWSAlgorithm.RS256);
        JWTClaimsSet ro = new JWTClaimsSet.Builder().subject("alice").build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).requestObject(new PlainJWT(ro))
                        .state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_REQUEST_OBJECT);
    }

    /**
     * Test success case of having non signed request object and registered algorithm 'none'
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectAlgMatch()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        oidcCtx.getClientInformation().getOIDCMetadata().setRequestObjectJWSAlg(new JWSAlgorithm("none"));
        JWTClaimsSet ro = new JWTClaimsSet.Builder().subject("alice").build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).requestObject(new PlainJWT(ro))
                        .state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test failure case of mismatch in client_id values
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectClientMismatch()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        JWTClaimsSet ro = new JWTClaimsSet.Builder().claim("client_id", "not_matching").build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).requestObject(new PlainJWT(ro))
                        .state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_REQUEST_OBJECT);
    }

    /**
     * Test failure in case of mismatch in response_type values
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectRespTypeMismatch()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        JWTClaimsSet ro = new JWTClaimsSet.Builder().claim("response_type", "id_token").build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).requestObject(new PlainJWT(ro))
                        .state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_REQUEST_OBJECT);
    }

    /**
     * Test success in case of matching client_id and response_type values
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectClientRespTypeMatch()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        JWTClaimsSet ro =
                new JWTClaimsSet.Builder().claim("client_id", "000123").claim("response_type", "code token").build();
        ResponseType rt = new ResponseType();
        rt.add(ResponseType.Value.CODE);
        rt.add(ResponseType.Value.TOKEN);
        AuthenticationRequest req = new AuthenticationRequest.Builder(rt, new Scope("openid"), new ClientID("000123"),
                URI.create("https://example.com/callback")).requestObject(new PlainJWT(ro)).nonce(new Nonce())
                        .state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test success case of RS256 signed request object.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectSignedWithRS256() throws NoSuchAlgorithmException, ComponentInitializationException,
            URISyntaxException, JOSEException, InvalidAlgorithmParameterException {
        JWSSigner signer = new RSASSASigner(kp.getPrivate());
        JWTClaimsSet ro = new JWTClaimsSet.Builder().subject("alice").build();
        SignedJWT signed = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), ro);
        signed.sign(signer);
        AuthenticationRequest req =
                new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), new ClientID("000123"),
                        URI.create("https://example.com/callback")).requestObject(signed).state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
    }

    /**
     * Test case of signature not matching any key.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectSignedNotVerified() throws NoSuchAlgorithmException, ComponentInitializationException,
            URISyntaxException, JOSEException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kp = kpg.generateKeyPair();
        JWSSigner signer = new RSASSASigner(kp.getPrivate());
        JWTClaimsSet ro = new JWTClaimsSet.Builder().subject("alice").build();
        SignedJWT signed = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), ro);
        signed.sign(signer);
        AuthenticationRequest req =
                new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), new ClientID("000123"),
                        URI.create("https://example.com/callback")).requestObject(signed).state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_REQUEST_OBJECT);
    }

    /**
     * Test case of request object signed with wrong type of algorithm.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectSignedWithUnexpectedAlgorithm() throws NoSuchAlgorithmException,
            ComponentInitializationException, URISyntaxException, JOSEException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        KeyPair kp = kpg.generateKeyPair();
        kpg.initialize(Curve.P_256.toECParameterSpec());
        JWSSigner signer = new ECDSASigner((ECPrivateKey) kp.getPrivate());
        JWTClaimsSet ro = new JWTClaimsSet.Builder().subject("alice").build();
        SignedJWT signed = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), ro);
        signed.sign(signer);
        AuthenticationRequest req =
                new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), new ClientID("000123"),
                        URI.create("https://example.com/callback")).requestObject(signed).state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_REQUEST_OBJECT);
    }

    /**
     * Test signed request object but no sec params context.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectSignedWithRS256NoSecParamsCtxt() throws NoSuchAlgorithmException,
            ComponentInitializationException, URISyntaxException, JOSEException, InvalidAlgorithmParameterException {
        prc.removeSubcontext(SecurityParametersContext.class);
        JWSSigner signer = new RSASSASigner(kp.getPrivate());
        JWTClaimsSet ro = new JWTClaimsSet.Builder().subject("alice").build();
        SignedJWT signed = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), ro);
        signed.sign(signer);
        AuthenticationRequest req =
                new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), new ClientID("000123"),
                        URI.create("https://example.com/callback")).requestObject(signed).state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_SEC_CFG);
    }

    /**
     * Test signed request object but no sec params.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectSignedWithRS256NoSecParams() throws NoSuchAlgorithmException,
            ComponentInitializationException, URISyntaxException, JOSEException, InvalidAlgorithmParameterException {
        prc.getSubcontext(SecurityParametersContext.class).setSignatureSigningParameters(null);
        JWSSigner signer = new RSASSASigner(kp.getPrivate());
        JWTClaimsSet ro = new JWTClaimsSet.Builder().subject("alice").build();
        SignedJWT signed = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), ro);
        signed.sign(signer);
        AuthenticationRequest req =
                new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), new ClientID("000123"),
                        URI.create("https://example.com/callback")).requestObject(signed).state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_SEC_CFG);
    }

    /**
     * Test signed request object but no credentials is sec params.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testRequestObjectSignedWithRS256NoCredsInSecParams() throws NoSuchAlgorithmException,
            ComponentInitializationException, URISyntaxException, JOSEException, InvalidAlgorithmParameterException {
        ((OIDCSignatureValidationParameters) (prc.getSubcontext(SecurityParametersContext.class)
                .getSignatureSigningParameters())).getValidationCredentials().clear();
        JWSSigner signer = new RSASSASigner(kp.getPrivate());
        JWTClaimsSet ro = new JWTClaimsSet.Builder().subject("alice").build();
        SignedJWT signed = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), ro);
        signed.sign(signer);
        AuthenticationRequest req =
                new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), new ClientID("000123"),
                        URI.create("https://example.com/callback")).requestObject(signed).state(new State()).build();
        prc.getInboundMessageContext().setMessage(req);
        oidcRespCtx.setRequestObject(req.getRequestObject());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_SEC_CFG);
    }

}