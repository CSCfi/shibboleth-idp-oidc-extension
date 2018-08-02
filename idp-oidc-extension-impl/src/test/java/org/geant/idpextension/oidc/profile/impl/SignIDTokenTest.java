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

import java.net.URISyntaxException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.profile.action.EventIds;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/** {@link SignIDToken} unit test. */
public class SignIDTokenTest extends BaseOIDCResponseActionTest {

    private SignIDToken action = new SignIDToken();

    String secret =
            "longsecretlongsecretlongsecretlongsecretlongsecretlongsecretlongsecretlongsecretlongsecretlongsecretlongsecretlongsecret";

    SecurityParametersContext spCtx;

    private void init(String algo, Credential credential) throws ComponentInitializationException, URISyntaxException {
        action.initialize();
        spCtx = new SecurityParametersContext();
        SignatureSigningParameters params = new SignatureSigningParameters();
        spCtx.setSignatureSigningParameters(params);
        params.setSigningCredential(credential);
        params.setSignatureAlgorithm(algo);
        profileRequestCtx.addSubcontext(spCtx);
        OIDCClientInformation information =
                new OIDCClientInformation(new ClientID(), new Date(), new OIDCClientMetadata(), new Secret(secret));
        metadataCtx.setClientInformation(information);
    }

    /**
     * Test that action does nothing if there is no sec ctx
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoSecCtx() throws ComponentInitializationException {
        action.initialize();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getSignedToken());
    }

    /**
     * Test that action does nothing if there is no signing parameters
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testNoSigningParameters() throws ComponentInitializationException, URISyntaxException {
        init("RS256", credentialRSA);
        spCtx.setSignatureSigningParameters(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getSignedToken());
    }

    /**
     * Test that action fails if there is no id token
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testNoIdToken() throws ComponentInitializationException, URISyntaxException {
        init("RS256", credentialRSA);
        final Event event = action.execute(requestCtx);
        respCtx.setIDToken(null);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    private void testSuccessMessage(JWSVerifier verifier)
            throws ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        setIdTokenToResponseContext("iss", "sub", "aud", new Date(), new Date());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(respCtx.getSignedToken());
        Assert.assertTrue(respCtx.getSignedToken().verify(verifier));

    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws JOSEException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSuccessMessageRS256()
            throws ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        init("RS256", credentialRSA);
        testSuccessMessage(new RSASSAVerifier((RSAPublicKey) credentialRSA.getPublicKey()));

    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws JOSEException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSuccessMessageRS384()
            throws ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        init("RS384", credentialRSA);
        testSuccessMessage(new RSASSAVerifier((RSAPublicKey) credentialRSA.getPublicKey()));
    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws JOSEException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSuccessMessageRS512()
            throws ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        init("RS512", credentialRSA);
        testSuccessMessage(new RSASSAVerifier((RSAPublicKey) credentialRSA.getPublicKey()));

    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws JOSEException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSuccessMessageES256()
            throws ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        init("ES256", credentialEC256);
        testSuccessMessage(new ECDSAVerifier((ECPublicKey) credentialEC256.getPublicKey()));

    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws JOSEException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSuccessMessageES384()
            throws ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        init("ES384", credentialEC384);
        testSuccessMessage(new ECDSAVerifier((ECPublicKey) credentialEC384.getPublicKey()));

    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws JOSEException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSuccessMessageES512()
            throws ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        init("ES512", credentialEC512);
        testSuccessMessage(new ECDSAVerifier((ECPublicKey) credentialEC512.getPublicKey()));

    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws JOSEException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSuccessMessageHS256()
            throws ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        init("HS256", credentialHMAC);
        testSuccessMessage(new MACVerifier(metadataCtx.getClientInformation().getSecret().getValue()));
    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws JOSEException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSuccessMessageHS384()
            throws ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        init("HS384", credentialHMAC);
        testSuccessMessage(new MACVerifier(metadataCtx.getClientInformation().getSecret().getValue()));
    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     * @throws JOSEException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSuccessMessageHS512()
            throws ComponentInitializationException, URISyntaxException, JOSEException, ParseException {
        init("HS512", credentialHMAC);
        testSuccessMessage(new MACVerifier(metadataCtx.getClientInformation().getSecret().getValue()));
    }

}