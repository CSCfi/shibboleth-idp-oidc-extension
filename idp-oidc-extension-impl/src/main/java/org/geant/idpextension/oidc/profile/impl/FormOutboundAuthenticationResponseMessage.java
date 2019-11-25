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

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestResponseModeLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestStateLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

/**
 * Action that forms outbound message based on request and response context. Formed message is set to
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 */
@SuppressWarnings("rawtypes")
public class FormOutboundAuthenticationResponseMessage extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(FormOutboundAuthenticationResponseMessage.class);

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        // Should not ever happen
        if (getOidcResponseContext().getRedirectURI() == null) {
            log.error("{} redirect uri must be validated to form response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        AuthenticationResponse resp = new AuthenticationSuccessResponse(getOidcResponseContext().getRedirectURI(),
                getOidcResponseContext().getAuthorizationCode(), getOidcResponseContext().getProcessedToken(),
                getOidcResponseContext().getAccessToken(),
                new DefaultRequestStateLookupFunction().apply(profileRequestContext), null,
                new DefaultRequestResponseModeLookupFunction().apply(profileRequestContext));
        profileRequestContext.getOutboundMessageContext().setMessage(resp);
    }
}