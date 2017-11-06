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
