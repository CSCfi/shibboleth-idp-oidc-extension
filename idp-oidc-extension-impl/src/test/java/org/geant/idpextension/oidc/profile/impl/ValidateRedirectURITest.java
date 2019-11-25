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

import java.net.URI;
import java.net.URISyntaxException;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/** {@link ValidateRedirectURI} unit test. */
public class ValidateRedirectURITest extends BaseOIDCResponseActionTest {

    private ValidateRedirectURI action;

    private void init() throws ComponentInitializationException {
        action = new ValidateRedirectURI();
        action.initialize();
    }

    /**
     * Test that action copes with no oidc metadata contextcontext.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoCtx() throws ComponentInitializationException {
        init();
        profileRequestCtx.getInboundMessageContext().removeSubcontext(OIDCMetadataContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test case of not having matching redirect uri.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @Test
    public void testNoMatch() throws ComponentInitializationException, URISyntaxException {
        init();
        OIDCMetadataContext oidcCtx = profileRequestCtx.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        OIDCClientMetadata metaData = new OIDCClientMetadata();
        metaData.setRedirectionURI(new URI("https://notmatching.org"));
        OIDCClientInformation information = new OIDCClientInformation(new ClientID("test"), null, metaData, null, null, null);
        oidcCtx.setClientInformation(information);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_REDIRECT_URI);
        Assert.assertNull(respCtx.getRedirectURI());
    }

    /**
     * Test case of having a match for redirect uri.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @Test
    public void testMatch() throws ComponentInitializationException, URISyntaxException {
        init();
        OIDCMetadataContext oidcCtx = profileRequestCtx.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        OIDCClientMetadata metaData = new OIDCClientMetadata();
        metaData.setRedirectionURI(new URI("https://client.example.org/cb"));
        OIDCClientInformation information = new OIDCClientInformation(new ClientID("test"), null, metaData, null, null, null);
        oidcCtx.setClientInformation(information);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(respCtx.getRedirectURI());
    }
}