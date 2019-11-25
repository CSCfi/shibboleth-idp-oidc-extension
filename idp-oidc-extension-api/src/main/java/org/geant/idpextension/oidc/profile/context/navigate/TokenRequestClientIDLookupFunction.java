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