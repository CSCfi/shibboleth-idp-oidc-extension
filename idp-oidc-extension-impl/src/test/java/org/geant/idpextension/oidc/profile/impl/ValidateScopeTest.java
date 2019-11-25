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
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/** {@link ValidateScope} unit test. */
public class ValidateScopeTest extends BaseOIDCResponseActionTest {

    private ValidateScope action;

    private OIDCClientMetadata metaData;

    @BeforeMethod
    private void init() throws ComponentInitializationException, URISyntaxException {
        action = new ValidateScope();
        action.initialize();
        OIDCMetadataContext oidcCtx =
                profileRequestCtx.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        metaData = new OIDCClientMetadata();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.OFFLINE_ACCESS);
        metaData.setScope(scope);
        metaData.setRedirectionURI(new URI("https://notmatching.org"));
        OIDCClientInformation information =
                new OIDCClientInformation(new ClientID("test"), null, metaData, null, null, null);
        oidcCtx.setClientInformation(information);
    }

    /**
     * Test that action filters our non valid scopes.
     */
    @Test
    public void testSuccess() throws ComponentInitializationException {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        // input is openid, profile, offline_access and email. profile and offline_access should be filtered out
        // (offline because the request is implicit).
        Assert.assertTrue(respCtx.getScope().contains(OIDCScopeValue.OPENID));
        Assert.assertTrue(respCtx.getScope().contains(OIDCScopeValue.EMAIL));
        Assert.assertTrue(!respCtx.getScope().contains(OIDCScopeValue.OFFLINE_ACCESS));
        Assert.assertTrue(!respCtx.getScope().contains(OIDCScopeValue.PROFILE));
    }

    /**
     * Test that action copes if there are no registered scopes.
     */
    @Test
    public void testSuccessNoScopes() throws ComponentInitializationException {
        metaData.setScope(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getScope());
    }

}