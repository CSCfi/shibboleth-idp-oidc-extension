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

import org.geant.idpextension.oidc.messaging.context.OIDCClientRegistrationResponseContext;
import org.mockito.Mockito;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.client.ClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/**
 * Base class for testing actions extending {@link AbstractOIDCClientMetadataPopulationAction}.
 */
public abstract class BaseOIDCClientMetadataPopulationTest {
    
    protected AbstractOIDCClientMetadataPopulationAction action;

    protected RequestContext requestCtx;
    protected ProfileRequestContext profileRequestCtx;

    protected void setUpContext(final OIDCClientMetadata input, final OIDCClientMetadata output) 
            throws ComponentInitializationException {
        OIDCClientRegistrationRequest request = new OIDCClientRegistrationRequest(null, input, null);
        requestCtx = new RequestContextBuilder().setInboundMessage(request).buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        profileRequestCtx.setOutboundMessageContext(new MessageContext<ClientInformationResponse>());
        OIDCClientRegistrationResponseContext responseCtx = new OIDCClientRegistrationResponseContext();
        responseCtx.setClientMetadata(output);
        profileRequestCtx.getOutboundMessageContext().addSubcontext(responseCtx);
    }
    
    @Test(expectedExceptions = ConstraintViolationException.class)
    protected void testNullInputStrategy() {
        action = constructAction();
        action.setOidcInputMetadataLookupStrategy(null);
    }

    @Test(expectedExceptions = ConstraintViolationException.class)
    protected void testNullOutputStrategy() {
        action = constructAction();
        action.setOidcOutputMetadataLookupStrategy(null);
    }
    
    @Test
    protected void testNoRequestMetadata() throws ComponentInitializationException {
        action = constructAction();
        action.setOidcInputMetadataLookupStrategy(initializeNullLookup());
        action.initialize();
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MSG_CTX);
    }

    @Test
    protected void testNoResponseMetadata() throws ComponentInitializationException {
        action = constructAction();
        action.setOidcOutputMetadataLookupStrategy(initializeNullLookup());
        action.initialize();
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_MSG_CTX);
    }

    protected ContextDataLookupFunction initializeNullLookup() throws ComponentInitializationException {
        setUpContext(new OIDCClientMetadata(), new OIDCClientMetadata());
        ContextDataLookupFunction lookup = Mockito.mock(ContextDataLookupFunction.class);
        Mockito.when(lookup.apply((ProfileRequestContext)Mockito.any())).thenReturn(null);
        return lookup;
    }

    protected abstract AbstractOIDCClientMetadataPopulationAction constructAction();
}
