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

import com.nimbusds.oauth2.sdk.id.Issuer;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.Criterion;

/**
 * A {@link Criterion} representing an OIDC (provider) issuer.
 */
public class IssuerCriterion implements Criterion {

    /** The issuer. */
    @Nonnull @NotEmpty private final Issuer issuer;

    /**
     * Constructor.
     * 
     * @param iss the issuer, can not be null or empty.
     */
    public IssuerCriterion(@Nonnull @NotEmpty final Issuer iss) {
        issuer = Constraint.isNotNull(iss, "Issuer cannot be null or empty");
    }

    /**
     * Gets the issuer.
     * 
     * @return the issuer, never null or empty.
     */
    @Nonnull @NotEmpty public Issuer getIssuer() {
        return issuer;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("IssuerCriterion [issuer=");
        builder.append(issuer);
        builder.append("]");
        return builder.toString();
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return issuer.hashCode();
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof IssuerCriterion) {
            return issuer.equals(((IssuerCriterion) obj).getIssuer());
        }

        return false;
    }
}
