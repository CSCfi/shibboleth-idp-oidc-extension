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

package org.geant.idpextension.oidc.messaging.context;

import java.util.Set;

import javax.annotation.Nullable;

import org.opensaml.messaging.context.BaseContext;

/**
 * Subcontext carrying information on metadata of the relying party. This
 * context appears as a subcontext of the
 * {@link org.opensaml.messaging.context.MessageContext} that carries the actual
 * OIDC request message, in such cases the metadata carried herein applies to
 * the issuer of that message.
 * 
 * This context is just a placeholder for the final solution. At first phase we
 * use only redirect uris.
 */
public class OIDCMetadataContext extends BaseContext {

    /** The only mandatory parameter. */
    @Nullable
    Set<String> redirectURIs;

    /**
     * Set of acceptable redirect uris rp may request response to.
     * 
     * @return redirect uris.
     */
    @Nullable
    public Set<String> getRedirectURIs() {
        return redirectURIs;
    }

    /**
     * Set the set of acceptable redirect uris for rp.
     * 
     * @param redirectURIs
     */
    public void setRedirectURIs(@Nullable Set<String> redirectURIs) {
        this.redirectURIs = redirectURIs;
    }

}