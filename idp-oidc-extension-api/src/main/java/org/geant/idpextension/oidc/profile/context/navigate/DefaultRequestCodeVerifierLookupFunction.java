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

import java.util.List;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.TokenRequest;

/**
 * For Token endpoint.
 * 
 * A function that returns code verifier value of the token request via a lookup function. This default lookup locates
 * code verifier from request if available. If information is not available, null is returned.
 */
public class DefaultRequestCodeVerifierLookupFunction extends AbstractTokenRequestLookupFunction<String> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(DefaultRequestCodeVerifierLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    String doLookup(TokenRequest req) {
        List<String> verifier = req.getAuthorizationGrant().toParameters().get("code_verifier");
        return verifier == null ? null : verifier.get(0);
    }
}