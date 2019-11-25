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

package org.geant.security.jwk;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.opensaml.security.credential.Credential;
import com.nimbusds.jose.Algorithm;

/** Credential based on JSON Web Key (JWK). */
public interface JWKCredential extends Credential {

    /**
     * Get kid of JWK.
     * 
     * @return kid parameter.
     */
    @Nullable
    public String getKid();

    /**
     * Get algorithm of JWK.
     * 
     * @return algorithm of JWK.
     */
    @Nonnull
    public Algorithm getAlgorithm();

}
