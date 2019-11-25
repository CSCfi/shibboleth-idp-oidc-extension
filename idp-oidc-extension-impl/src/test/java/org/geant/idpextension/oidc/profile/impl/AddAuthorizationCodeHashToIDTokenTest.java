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

/** {@link AddAuthorizationCodeHashToIDToken} unit test. */
public class AddAuthorizationCodeHashToIDTokenTest extends BaseOIDCResponseActionTest {

    private AddAuthorizationCodeHashToIDToken action;

    SecurityParametersContext spCtx;

    private void init(String algo, Credential credential) throws ComponentInitializationException, URISyntaxException {
        spCtx = new SecurityParametersContext();
        SignatureSigningParameters params = new SignatureSigningParameters();
        spCtx.setSignatureSigningParameters(params);
        params.setSigningCredential(credential);
        params.setSignatureAlgorithm(algo);
        profileRequestCtx.addSubcontext(spCtx);
        setIdTokenToResponseContext("iss", "sub", "aud", new Date(), new Date());
        respCtx.setAuthorizationCode("authcode");
        action = new AddAuthorizationCodeHashToIDToken();
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
     * Test that action copes with no authorization code in response context.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     * @throws URISyntaxException
     */
    @Test
    public void testAuthorizationCode() throws ComponentInitializationException, ParseException, URISyntaxException {
        init("RS256", credentialRSA);
        respCtx.setAuthorizationCode(null);
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
        Assert.assertNotNull(respCtx.getIDToken().getStringClaim("c_hash"));
    }

}