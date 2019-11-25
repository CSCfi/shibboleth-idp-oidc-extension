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
import com.nimbusds.openid.connect.sdk.Prompt;

/**
 * A function that returns copy of requested prompt via a lookup function. This default lookup locates prompt from oidc
 * authentication request if available. If information is not available, null is returned. If there is prompt in request
 * object it is used instead of prompt parameter.
 */
public class DefaultRequestedPromptLookupFunction extends AbstractAuthenticationRequestLookupFunction<Prompt> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DefaultRequestedPromptLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    Prompt doLookup(@Nonnull AuthenticationRequest req) {
        try {
            if (requestObject != null && requestObject.getJWTClaimsSet().getClaim("prompt") != null) {
                return Prompt.parse((String) requestObject.getJWTClaimsSet().getClaim("prompt"));
            }
        } catch (ParseException | com.nimbusds.oauth2.sdk.ParseException e) {
            log.error("Unable to parse prompt from request object prompt value");
            return null;
        }
        if (req.getPrompt() == null) {
            return null;
        }
        Prompt requestParameterPrompt = new Prompt();
        requestParameterPrompt.addAll(req.getPrompt());
        return requestParameterPrompt;
    }
}