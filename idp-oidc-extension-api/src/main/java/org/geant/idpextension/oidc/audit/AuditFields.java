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

package org.geant.idpextension.oidc.audit;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Constants to use for audit logging fields stored in an {@link net.shibboleth.idp.profile.context.AuditContext}.
 */
public final class AuditFields {

    
    /** OIDC client ID. */
    @Nonnull @NotEmpty public static final String CLIENT_ID = "SP";
    
    /** OIDC issuer. */
    @Nonnull @NotEmpty public static final String ISSUER = "IDP";

    /** The inbound (Nimbus) message class. */
    @Nonnull @NotEmpty public static final String INBOUND_MESSAGE_CLASS = "b";
    
    /** The outbound (Nimbus) message class. */
    @Nonnull @NotEmpty public static final String OUTBOUND_MESSAGE_CLASS = "bb";
    
    /** The authentication context reference value. */
    @Nonnull @NotEmpty public static final String ACR = "ac";

    /** The subject value. */
    @Nonnull @NotEmpty public static final String SUB_VALUE = "n";
    
    /** The subject format (public/pairwise). */
    @Nonnull @NotEmpty public static final String SUB_FORMAT = "f";

    /** The flag whether the id_token is encrypted. */
    @Nonnull @NotEmpty public static final String ENCRYPTED_ID_TOKEN = "X";

    /** prompt=none requested field. */
    @Nonnull @NotEmpty public static final String IS_PASSIVE = "pasv";

    /** prompt=login requested field. */
    @Nonnull @NotEmpty public static final String FORCE_AUTHN = "fauth";
    
    /** Revoked Token. */
    @Nonnull @NotEmpty public static final String REVOKED_TOKEN = "i";
    
    /**
     * Constructor.
     */
    private AuditFields() {
        // no op
    }

}
