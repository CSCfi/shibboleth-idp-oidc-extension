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

package org.geant.idpextension.oidc.profile.api;

import javax.annotation.Nullable;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;

import net.shibboleth.idp.profile.config.SecurityConfiguration;

/**
 * Class extends SecurityConfiguration to support separate configuration for request object decryption and signature
 * validation.
 */
public class OIDCSecurityConfiguration extends SecurityConfiguration {

    /** Configuration used when decrypting request object information. */
    @Nullable
    private EncryptionConfiguration requestObjectDecryptConfig;

    /** Configuration used when validating request object information. */
    @Nullable
    private SignatureSigningConfiguration requestObjectSignatureValidationConfig;

    /** Configuration used when validating token endpoint authentication JWT signatures. */
    @Nullable
    private SignatureSigningConfiguration tokenEndpointJwtSignatureValidationConfig;

    /**
     * Get the configuration used when decrypting request object information.
     * 
     * @return configuration used when decrypting request object information, or null
     */
    @Nullable
    public EncryptionConfiguration getRequestObjectDecryptionConfiguration() {
        return requestObjectDecryptConfig;
    }

    /**
     * Set the configuration used when decrypting request object information.
     * 
     * @param config configuration used when decrypting request object information, or null
     */
    public void setRequestObjectDecryptionConfiguration(@Nullable final EncryptionConfiguration config) {
        requestObjectDecryptConfig = config;
    }

    /**
     * Get the configuration used when validating request object information.
     * 
     * @return configuration used when validating request object information, or null
     */
    @Nullable
    public SignatureSigningConfiguration getRequestObjectSignatureValidationConfiguration() {
        return requestObjectSignatureValidationConfig;
    }

    /**
     * Set the configuration used when validating request object information.
     * 
     * @param configuration used when validating request object information, or null
     */
    public void setRequestObjectSignatureValidationConfiguration(@Nullable final SignatureSigningConfiguration config) {
        requestObjectSignatureValidationConfig = config;
    }

    /**
     * Get the configuration used when validating token endpoint authentication JWT signatures.
     * 
     * @return configuration used when validating token endpoint authentication JWT signatures, or null
     */
    @Nullable
    public SignatureSigningConfiguration getTokenEndpointJwtSignatureValidationConfiguration() {
        return tokenEndpointJwtSignatureValidationConfig;
    }

    /**
     * Set the configuration used when validating token endpoint authentication JWT signatures.
     * 
     * @param configuration used when validating token endpoint authentication JWT signatures, or null
     */
    public void setTokenEndpointJwtSignatureValidationConfiguration(@Nullable final SignatureSigningConfiguration config) {
        tokenEndpointJwtSignatureValidationConfig = config;
    }

}
