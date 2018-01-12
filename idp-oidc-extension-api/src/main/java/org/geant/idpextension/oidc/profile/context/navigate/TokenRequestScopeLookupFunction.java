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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.text.ParseException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.Scope;

/**
 * A function that returns copy of requested scope via a lookup function. This
 * lookup locates scope from oidc authz code for token request handling. If
 * authz code claims are not available, null is returned.
 */
@SuppressWarnings("rawtypes")
public class TokenRequestScopeLookupFunction extends AbstractIdentifiableInitializableComponent
        implements ContextDataLookupFunction<ProfileRequestContext, Scope> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(TokenRequestScopeLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Scope apply(@Nullable final ProfileRequestContext input) {
        if (input == null || input.getOutboundMessageContext() == null) {
            return null;
        }
        OIDCAuthenticationResponseContext oidcResponseContext = input.getOutboundMessageContext()
                .getSubcontext(OIDCAuthenticationResponseContext.class, false);
        if (oidcResponseContext == null) {
            return null;
        }
        JWTClaimsSet authzCodeClaims = oidcResponseContext.getAuthorizationCodeClaims();
        // TODO: add constant for scope claim name
        if (authzCodeClaims == null || authzCodeClaims.getClaim("scope") == null) {
            return null;
        }
        Scope scope = null;
        try {
            scope = Scope.parse((authzCodeClaims.getStringClaim("scope")));
        } catch (ParseException e) {
            log.error("Unable to parse scope from authz code claim {}", authzCodeClaims.getClaim("scope").toString());
        }
        return scope;

    }

}