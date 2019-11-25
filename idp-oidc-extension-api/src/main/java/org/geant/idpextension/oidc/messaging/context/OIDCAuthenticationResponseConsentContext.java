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

package org.geant.idpextension.oidc.messaging.context;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.opensaml.messaging.context.BaseContext;
import net.minidev.json.JSONArray;

/**
 * Subcontext carrying user consent information in a form suitable for OIDC processing. The information is carried in
 * tokens (code, refresh token, access token) to back channel endpoints. This context appears as a subcontext of the
 * {@link OIDCAuthenticationResponseContext}.
 */
public class OIDCAuthenticationResponseConsentContext extends BaseContext {

    /** Attributes having consent. */
    @Nullable
    private JSONArray consentedAttributes;

    /** Attributes requiring consent. */
    @Nullable
    private JSONArray consentableAttributes;

    /**
     * Constructor.
     */
    public OIDCAuthenticationResponseConsentContext() {
        consentedAttributes = new JSONArray();
        consentableAttributes = new JSONArray();
    }

    /**
     * Get consented attributes.
     * 
     * @return consented attributes.
     */
    @Nonnull
    public JSONArray getConsentedAttributes() {
        return consentedAttributes;
    }

    /**
     * Get consentable attributes.
     * 
     * @return consentable attributes.
     */
    @Nonnull
    public JSONArray getConsentableAttributes() {
        return consentableAttributes;
    }

}