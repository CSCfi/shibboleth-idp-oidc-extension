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

package org.geant.idpextension.oidc.security.impl;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;

import org.geant.security.jwk.JWKCredential;
import org.opensaml.xmlsec.SignatureSigningParameters;

/**
 * OIDC Signature Validation Parameters. Steals a bit SignatureSigningParameters as extending it also for validation
 * purposes.
 */
public class OIDCSignatureValidationParameters extends SignatureSigningParameters {

    /** The list of validation credentials. */
    @Nonnull
    final private List<JWKCredential> validationCredentials = new ArrayList<JWKCredential>();

    /**
     * Get the list of validation credentials.
     * 
     * @return the list of validation credentials
     */
    @Nonnull
    public List<JWKCredential> getValidationCredentials() {
        return validationCredentials;
    }
}
