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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;

/**
 * A function that returns auth time via a lookup function. This lookup locates auth time from authentication context.
 * If auth time is not available, null is returned.
 */
@SuppressWarnings("rawtypes")
public class DefaultAuthTimeLookupFunction implements ContextDataLookupFunction<ProfileRequestContext, Long> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(DefaultAuthTimeLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Long apply(@Nullable final ProfileRequestContext input) {
        if (input == null) {
            return null;
        }
        AuthenticationContext authCtx = input.getSubcontext(AuthenticationContext.class, false);
        if (authCtx == null) {
            return null;
        }
        AuthenticationResult authResult = authCtx.getAuthenticationResult();
        if (authResult == null) {
            return null;
        }
        return authResult.getAuthenticationInstant();

    }

}