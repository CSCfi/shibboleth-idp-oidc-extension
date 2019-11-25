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
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;

import net.minidev.json.JSONObject;

/**
 * A function that returns copy of requested claims via a lookup function. This default lookup locates requested claims
 * from oidc authentication request if available. If information is not available, null is returned. If there is claims
 * request in request object it is used instead of claims parameter.
 */
public class DefaultRequestedClaimsLookupFunction extends AbstractAuthenticationRequestLookupFunction<ClaimsRequest> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DefaultRequestedClaimsLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    ClaimsRequest doLookup(@Nonnull AuthenticationRequest req) {
        try {
            if (requestObject != null && requestObject.getJWTClaimsSet().getClaim("claims") != null) {
                Object claims = requestObject.getJWTClaimsSet().getClaim("claims");
                if (claims instanceof JSONObject) {
                    return ClaimsRequest.parse((JSONObject) claims);
                } else {
                    log.error("claims claim is not of expected type");
                    return null;
                }
            }
        } catch (ParseException e) {
            log.error("unable to parse claims claim {}", e.getMessage());
            return null;
        }
        if (req.getClaims() == null) {
            return null;
        }
        ClaimsRequest request = new ClaimsRequest();
        request.add(req.getClaims());
        return request;
    }
}