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

    /** unspecified auth ctx class.*/
    public static final String UNSPECIFIED = "org.geant.idpextension.oidc.authn.principal.string.unspecified";

    /** The class ref. */
    @Nonnull
    @NotEmpty
    private String authnContextClassReference;
    
    /**
     * Constructor.
     * 
     * @param classRef
     *            the class reference URI
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
        final AuthenticationContextClassReferencePrincipal copy = (AuthenticationContextClassReferencePrincipal) super
                .clone();
        copy.authnContextClassReference = authnContextClassReference;
        return copy;
    }
}