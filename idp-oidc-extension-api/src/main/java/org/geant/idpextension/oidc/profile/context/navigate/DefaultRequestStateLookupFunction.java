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

import java.text.ParseException;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

/**
 * A function that returns copy of the state the request via a lookup function. This default lookup locates state from
 * oidc authentication request if available. If information is not available, null is returned. If there is state in request
 * object it is used instead of state parameter.
 */
public class DefaultRequestStateLookupFunction extends AbstractAuthenticationRequestLookupFunction<State> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DefaultRequestStateLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    State doLookup(@Nonnull AuthenticationRequest req) {
        try {
            if (requestObject != null && requestObject.getJWTClaimsSet().getClaim("state") != null) {
                Object state = requestObject.getJWTClaimsSet().getClaim("state");
                if (state instanceof String) {
                    return new State((String) state);
                } else {
                    log.error("state claim is not of expected type");
                    return null;
                }
            }
        } catch (ParseException e) {
            log.error("Unable to parse state from request object state value");
            return null;
        }
        if (req.getState() == null) {
            return null;
        }
        return new State(req.getState().getValue());
    }
}