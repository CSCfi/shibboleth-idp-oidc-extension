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
    /**
     * Constructor.
     */
    private AuditFields() {
        // no op
    }

}
