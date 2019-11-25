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

package org.geant.idpextension.oidc.authn.principal;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.principal.CloneablePrincipal;
import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import com.google.common.base.MoreObjects;

/** Principal based on a OIDC Authentication Context Class Reference. */
public final class AuthenticationContextClassReferencePrincipal implements CloneablePrincipal {

    /** unspecified auth ctx class. */
    public static final String UNSPECIFIED = "org.geant.idpextension.oidc.authn.principal.string.unspecified";

    /** The class ref. */
    @Nonnull
    @NotEmpty
    private String authnContextClassReference;

    /**
     * Constructor.
     * 
     * @param classRef the class reference URI
     */
    public AuthenticationContextClassReferencePrincipal(
            @Nonnull @NotEmpty @ParameterName(name = "classRef") final String classRef) {
        authnContextClassReference = Constraint.isNotNull(StringSupport.trimOrNull(classRef),
                "AuthnContextClassRef cannot be null or empty");
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NotEmpty
    public String getName() {
        return authnContextClassReference;
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return authnContextClassReference.hashCode();
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(final Object other) {
        if (other == null) {
            return false;
        }

        if (this == other) {
            return true;
        }

        if (other instanceof AuthenticationContextClassReferencePrincipal) {
            return authnContextClassReference.equals(((AuthenticationContextClassReferencePrincipal) other).getName());
        }

        return false;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this).add("authnContextClassReference", authnContextClassReference)
                .toString();
    }

    /** {@inheritDoc} */
    @Override
    public AuthenticationContextClassReferencePrincipal clone() throws CloneNotSupportedException {
        final AuthenticationContextClassReferencePrincipal copy =
                (AuthenticationContextClassReferencePrincipal) super.clone();
        copy.authnContextClassReference = authnContextClassReference;
        return copy;
    }
}