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
     * The grant type in token request is not supported for RP.
     */
    @Nonnull @NotEmpty public static final String INVALID_GRANT_TYPE = "InvalidGrantType";
    
    /**
     * The subject resolved is not the expected one.
     */
    @Nonnull @NotEmpty public static final String INVALID_SUBJECT = "InvalidSubject";
    
    /**
     * Both request uri and request object in request.
     */
    @Nonnull @NotEmpty public static final String REQUEST_OBJECT_AND_URI = "RequestObjectAndUri";
    
    /**
     * The request object cannot be validated.
     */
    @Nonnull @NotEmpty public static final String INVALID_REQUEST_OBJECT = "InvalidRequestObject";
    
    /**
     * The request uri is invalid.
     */
    @Nonnull @NotEmpty public static final String INVALID_REQUEST_URI = "InvalidRequestUri";

    /**
     * Constructor.
     */
    private OidcEventIds() {
        // no op
    }

}
