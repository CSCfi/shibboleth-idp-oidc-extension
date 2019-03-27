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
