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

package org.geant.idpextension.oidc.profile;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * OpenID Connect -specific constants to use for {@link org.opensaml.profile.action.ProfileAction}
 * {@link org.opensaml.profile.context.EventContext}s.
 */
public final class OidcEventIds {

    /**
     * ID of event returned if the mandatory redirect_uris is missing.
     */
    @Nonnull @NotEmpty public static final String MISSING_REDIRECT_URIS = "MissingRedirectionURIs";

    /**
     * ID of event returned if the mandatory redirect_uris is invalid.
     */
    @Nonnull @NotEmpty public static final String INVALID_REDIRECT_URIS = "InvalidRedirectionURIs";
    
    /**
     * ID of event returned if the WebFinger rel is invalid / not supported.
     */
    @Nonnull @NotEmpty public static final String INVALID_WEBFINGER_REL = "InvalidWebFingerRel";
    
    /**
     * The provided authorization grant is invalid.
     */
    @Nonnull @NotEmpty public static final String INVALID_GRANT = "InvalidGrant";
    
    /**
     * The redirect_uri in request is invalid.
     */
    @Nonnull @NotEmpty public static final String INVALID_REDIRECT_URI = "InvalidRedirectionURI";
    
    /**
     * The response type in request is not supported for RP.
     */
    @Nonnull @NotEmpty public static final String INVALID_RESPONSE_TYPE = "InvalidResponseType";
    
    /**
     * The subject resolved is not the expected one.
     */
    @Nonnull @NotEmpty public static final String INVALID_SUBJECT = "InvalidSubject";

}
