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

package org.geant.idpextension.oidc.profile.context.navigate;

import javax.annotation.Nullable;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;

import com.nimbusds.oauth2.sdk.AbstractOptionallyAuthenticatedRequest;
import com.nimbusds.oauth2.sdk.AbstractOptionallyIdentifiedRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;

/**
 * For Token, Revocation and other end points supporting client authentication.
 * 
 * A function that returns client id of the request via a lookup function. This lookup locates client id primarily from
 * client authentication if available. If client authentication information is not available, client id is looked from
 * client_id parameter. Null is returned if information is not available.
 */
@SuppressWarnings("rawtypes")
public class TokenRequestClientIDLookupFunction implements ContextDataLookupFunction<MessageContext, ClientID> {

    /** {@inheritDoc} */
    @Override
    public ClientID apply(@Nullable MessageContext input) {
        if (input == null) {
            return null;
        }
        Object message = input.getMessage();
        if (!(message instanceof AbstractOptionallyAuthenticatedRequest)) {
            return null;
        }
        AbstractOptionallyAuthenticatedRequest req = (AbstractOptionallyAuthenticatedRequest) message;
        if (req.getClientAuthentication() != null && req.getClientAuthentication().getClientID() != null) {
            return req.getClientAuthentication().getClientID();
        }
        if (!(message instanceof AbstractOptionallyIdentifiedRequest)) {
            return null;
        }
        return ((AbstractOptionallyIdentifiedRequest) req).getClientID();
    }
}