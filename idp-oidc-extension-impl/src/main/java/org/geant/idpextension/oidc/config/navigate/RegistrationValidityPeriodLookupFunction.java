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

package org.geant.idpextension.oidc.config.navigate;

import javax.annotation.Nullable;

import org.geant.idpextension.oidc.config.OIDCDynamicRegistrationConfiguration;
import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.AbstractRelyingPartyLookupFunction;

/**
 * A function that returns {@link OIDCDynamicRegistrationConfiguration#getRegistrationValidityPeriod()}
 * if such a profile is available from a {@link RelyingPartyContext} obtained via a lookup function,
 * by default a child of the {@link ProfileRequestContext}.
 * 
 * <p>If a specific setting is unavailable, a null value is returned.</p>
 */
public class RegistrationValidityPeriodLookupFunction extends AbstractRelyingPartyLookupFunction<Long> {

    /** {@inheritDoc} */
    @Override
    @Nullable public Long apply(@Nullable final ProfileRequestContext input) {
        final RelyingPartyContext rpc = getRelyingPartyContextLookupStrategy().apply(input);
        if (rpc != null) {
            final ProfileConfiguration pc = rpc.getProfileConfig();
            if (pc != null && pc instanceof OIDCDynamicRegistrationConfiguration) {
                return ((OIDCDynamicRegistrationConfiguration) pc).getRegistrationValidityPeriod();
            }
        }
        
        return null;
    }
}