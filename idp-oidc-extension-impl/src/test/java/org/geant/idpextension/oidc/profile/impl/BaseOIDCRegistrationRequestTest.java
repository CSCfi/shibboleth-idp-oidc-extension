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

import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Base class for all unit tests related to dealing with OpenID Connect Dynamic Client Registration requests.
 */
@SuppressWarnings("rawtypes")
public abstract class BaseOIDCRegistrationRequestTest {

    protected RequestContext requestCtx;
    protected ProfileRequestContext profileRequestCtx;

    protected void setUpContext(final OIDCClientRegistrationRequest request) throws ComponentInitializationException {
        requestCtx = new RequestContextBuilder().setInboundMessage(request).buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
    }
}
