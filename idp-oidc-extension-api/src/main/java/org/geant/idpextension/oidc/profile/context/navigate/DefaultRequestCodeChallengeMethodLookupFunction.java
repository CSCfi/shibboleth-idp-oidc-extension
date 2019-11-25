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
 * A function that returns code challenge method value of the authentication request via a lookup function. This default
 * lookup locates code challenge method from oidc authentication request if available. If information is not available,
 * null is returned. If there is code_challenge_method in request object it is used instead of code_challenge_method
 * parameter.
 */
public class DefaultRequestCodeChallengeMethodLookupFunction
        extends AbstractAuthenticationRequestLookupFunction<String> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DefaultRequestCodeChallengeMethodLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    String doLookup(@Nonnull AuthenticationRequest req) {
        try {
            if (requestObject != null && requestObject.getJWTClaimsSet().getClaim("code_challenge_method") != null) {
                Object codeChallenge = requestObject.getJWTClaimsSet().getClaim("code_challenge_method");
                if (codeChallenge instanceof String) {
                    return (String) codeChallenge;
                } else {
                    log.error("code_challenge_method claim is not of expected type");
                    return null;
                }

            }
        } catch (ParseException e) {
            log.error("Unable to parse code challenge method  from request object code_challenge_method value");
            return null;
        }
        return req.getCodeChallengeMethod() == null ? null : req.getCodeChallengeMethod().getValue();
    }

}