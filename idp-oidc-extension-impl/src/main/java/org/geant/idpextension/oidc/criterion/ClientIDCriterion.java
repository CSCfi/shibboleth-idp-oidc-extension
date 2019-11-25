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

import com.nimbusds.oauth2.sdk.id.ClientID;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.Criterion;

/**
 * A {@link Criterion} representing an OIDC client ID.
 */
public class ClientIDCriterion implements Criterion {

    /** The client ID. */
    @Nonnull @NotEmpty private final ClientID id;

    /**
     * Constructor.
     * 
     * @param clientId the client ID, can not be null or empty.
     */
    public ClientIDCriterion(@Nonnull @NotEmpty final ClientID clientId) {
        id = Constraint.isNotNull(clientId, "Client ID cannot be null or empty");
    }

    /**
     * Gets the client ID.
     * 
     * @return the client ID, never null or empty.
     */
    @Nonnull @NotEmpty public ClientID getClientID() {
        return id;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("ClientIDCriterion [id=");
        builder.append(id);
        builder.append("]");
        return builder.toString();
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return id.hashCode();
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

        if (obj instanceof ClientIDCriterion) {
            return id.equals(((ClientIDCriterion) obj).getClientID());
        }

        return false;
    }
}
