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

/**
 * A function that returns authentication max age parameter the request via a lookup function. This default lookup
 * locates max age from oidc authentication request if available. If information is not available, null is returned. If
 * there is max_age parameter in request object it is used instead of max_age request parameter.
 */
public class DefaultRequestMaxAgeLookupFunction extends AbstractAuthenticationRequestLookupFunction<Long> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DefaultRequestMaxAgeLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    Long doLookup(@Nonnull AuthenticationRequest req) {
        try {
            if (requestObject != null && requestObject.getJWTClaimsSet().getClaim("max_age") != null) {
                return new Long(requestObject.getJWTClaimsSet().getIntegerClaim("max_age"));
            }
        } catch (ParseException e) {
            log.error("Unable to parse state from request object state value");
            return null;
        }
        return req.getMaxAge() == -1 ? null : new Long(req.getMaxAge());
    }
}