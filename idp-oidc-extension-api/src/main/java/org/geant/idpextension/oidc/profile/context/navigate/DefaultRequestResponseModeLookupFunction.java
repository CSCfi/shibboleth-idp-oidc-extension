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
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

/**
 * A function that returns copy of the response mode of the request via a lookup function. This default lookup locates
 * response mode from oidc authentication request if available. If information is not available, null is returned. If
 * there is response mode in request object it is used instead of response_mode parameter.
 */
public class DefaultRequestResponseModeLookupFunction
        extends AbstractAuthenticationRequestLookupFunction<ResponseMode> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DefaultRequestResponseModeLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    ResponseMode doLookup(@Nonnull AuthenticationRequest req) {
        try {
            if (requestObject != null && requestObject.getJWTClaimsSet().getClaim("response_mode") != null) {
                Object rMode = requestObject.getJWTClaimsSet().getClaim("response_mode");
                if (rMode instanceof String) {
                    return new ResponseMode((String) rMode);
                } else {
                    log.error("response_mode claim is not of expected type");
                    return null;
                }
            }
        } catch (ParseException e) {
            log.error("Unable to parse response mode from request object response_mode value");
            return null;
        }
        if (req.getResponseMode() == null) {
            return null;
        }
        ResponseMode responseMode = new ResponseMode(req.getResponseMode().getValue());
        return responseMode;
    }
}