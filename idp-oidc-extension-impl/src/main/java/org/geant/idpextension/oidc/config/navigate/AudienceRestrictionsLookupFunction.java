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

import java.util.Collection;
import java.util.Collections;

import javax.annotation.Nullable;

import org.geant.idpextension.oidc.config.OIDCCoreProtocolConfiguration;
import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableCollection.Builder;

import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.AbstractRelyingPartyLookupFunction;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;

/**
 * A function that returns the effective audience restrictions to include in ID tokens, based on combining a relying
 * party's entityID with the result of {@link OIDCCoreProtocolConfiguration#getAdditionalAudiencesForIdToken()}, if such
 * a profile is available from a {@link RelyingPartyContext} obtained via a lookup function, by default a child of the
 * {@link ProfileRequestContext}.
 * 
 * <p>
 * If a specific setting is unavailable, no values are returned.
 * </p>
 */
public class AudienceRestrictionsLookupFunction extends AbstractRelyingPartyLookupFunction<Collection<String>> {

    /** {@inheritDoc} */
    @Override @Nullable @NonnullElements @NotLive @Unmodifiable public Collection<String> apply(
            @Nullable final ProfileRequestContext input) {
        final RelyingPartyContext rpc = getRelyingPartyContextLookupStrategy().apply(input);
        if (rpc != null) {
            final String id = rpc.getRelyingPartyId();
            final ProfileConfiguration pc = rpc.getProfileConfig();
            if (pc != null && pc instanceof OIDCCoreProtocolConfiguration
                    && !((OIDCCoreProtocolConfiguration) pc).getAdditionalAudiencesForIdToken().isEmpty()) {
                final Builder<String> builder = ImmutableList.builder();
                if (id != null) {
                    builder.add(rpc.getRelyingPartyId());
                }
                builder.addAll(((OIDCCoreProtocolConfiguration) pc).getAdditionalAudiencesForIdToken());
                return builder.build();
            } else if (id != null) {
                return ImmutableList.<String> of(rpc.getRelyingPartyId());
            }
        }

        return Collections.emptyList();
    }

}