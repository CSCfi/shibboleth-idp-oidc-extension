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

package org.geant.idpextension.oidc.profile.context.navigate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.id.ClientID;

/**
 * For UserInfo end point.
 * 
 * A function that returns client id of the request via a lookup function. This lookup locates client id from access
 * token used for user info request if available. If information is not available, null is returned.
 */
@SuppressWarnings("rawtypes")
public class UserInfoRequestClientIDLookupFunction implements ContextDataLookupFunction<MessageContext, ClientID> {

    /** Logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(UserInfoRequestClientIDLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    public ClientID apply(@Nullable MessageContext input) {
        if (input == null) {
            return null;
        }
        if (!(input.getParent() instanceof ProfileRequestContext)) {
            return null;
        }
        MessageContext msgCtx = ((ProfileRequestContext) input.getParent()).getOutboundMessageContext();
        if (msgCtx == null) {
            return null;
        }
        OIDCAuthenticationResponseContext ctx = msgCtx.getSubcontext(OIDCAuthenticationResponseContext.class, false);
        if (ctx == null || ctx.getTokenClaimsSet() == null) {
            return null;
        }
        return ctx.getTokenClaimsSet().getClientID();

    }
}