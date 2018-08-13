/*
 * GÉANT BSD Software License
 *
 * Copyright (c) 2017 - 2020, GÉANT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the GÉANT nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Disclaimer:
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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