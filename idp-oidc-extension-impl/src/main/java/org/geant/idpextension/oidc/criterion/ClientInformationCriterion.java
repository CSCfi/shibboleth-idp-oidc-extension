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

package org.geant.idpextension.oidc.criterion;

import javax.annotation.Nonnull;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.Criterion;

/**
 * Client information criterion to make decisions based on client information. Usually used by
 * {@link OIDCClientInformationSignatureSigningParametersResolver}.
 */
public class ClientInformationCriterion implements Criterion {

    /** Client information. */
    @Nonnull
    private OIDCClientInformation oidcClientInformation;

    /**
     * Get client information.
     * 
     * @return client information
     */
    public OIDCClientInformation getOidcClientInformation() {
        return oidcClientInformation;
    }

    /**
     * Constructor.
     * 
     * @param information client information
     */
    public ClientInformationCriterion(@Nonnull final OIDCClientInformation information) {
        oidcClientInformation = Constraint.isNotNull(information, "client information cannot be null");
    }
}
