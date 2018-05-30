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

import com.nimbusds.oauth2.sdk.ParseException;

/** {@link InitializeAuthenticationContext} unit test. */
public class AddAccessTokenHashToIDTokenTest extends BaseOIDCResponseActionTest {

    private AddAccessTokenHashToIDToken action;

    SecurityParametersContext spCtx;

    private void init(String algo, Credential credential) throws ComponentInitializationException, URISyntaxException {
        spCtx = new SecurityParametersContext();
        SignatureSigningParameters params = new SignatureSigningParameters();
        spCtx.setSignatureSigningParameters(params);
        params.setSigningCredential(credential);
        params.setSignatureAlgorithm(algo);
        profileRequestCtx.addSubcontext(spCtx);
        setIdTokenToResponseContext("iss", "sub", "aud", new Date(), new Date());
        respCtx.setAccessToken("accesstoken", 100);
        action = new AddAccessTokenHashToIDToken();
        action.initialize();
    }

    /**
     * Test that action copes with no id token in response context.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     * @throws URISyntaxException
     */
    @Test
    public void testNoIdToken() throws ComponentInitializationException, ParseException, URISyntaxException {
        init("RS256", credentialRSA);
        respCtx.setIDToken(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test that action copes with no access token in response context.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     * @throws URISyntaxException
     */
    @Test
    public void testNoAccessToken() throws ComponentInitializationException, ParseException, URISyntaxException {
        init("RS256", credentialRSA);
        respCtx.setAccessToken(null, 0);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test that action hash is produced to id token.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     * @throws URISyntaxException
     */
    @Test
    public void testSuccess() throws ComponentInitializationException, ParseException, URISyntaxException {
        init("RS256", credentialRSA);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(respCtx.getIDToken().getStringClaim("at_hash"));
    }

}