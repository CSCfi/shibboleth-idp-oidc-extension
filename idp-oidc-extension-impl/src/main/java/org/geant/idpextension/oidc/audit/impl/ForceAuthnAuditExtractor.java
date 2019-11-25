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

package org.geant.idpextension.oidc.audit.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Prompt;

import net.shibboleth.utilities.java.support.logic.Constraint;

/** {@link Function} that returns true is prompt contains login in {@link AuthenticationRequest}. */
public class ForceAuthnAuditExtractor implements Function<ProfileRequestContext, Boolean> {

    /** Lookup strategy for message to read from. */
    @Nonnull
    private final Function<ProfileRequestContext, AuthenticationRequest> requestLookupStrategy;

    /**
     * Constructor.
     *
     * @param strategy lookup strategy for message
     */
    public ForceAuthnAuditExtractor(@Nonnull final Function<ProfileRequestContext, AuthenticationRequest> strategy) {
        requestLookupStrategy = Constraint.isNotNull(strategy, "AuthenticationRequest lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Boolean apply(@Nullable final ProfileRequestContext input) {
        final AuthenticationRequest request = requestLookupStrategy.apply(input);
        if (request != null && request.getPrompt() != null) {
            return request.getPrompt().contains(Prompt.Type.LOGIN);
        }

        return null;
    }

}