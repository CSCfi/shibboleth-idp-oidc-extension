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

import org.opensaml.messaging.context.BaseContext;

/**
 * Base subcontext carrying information on response formed for OIDC relying partys. This context (and the ones
 * extending it) appear as a subcontext of the {@link org.opensaml.messaging.context.MessageContext}.
 */
public class BaseOIDCResponseContext extends BaseContext {

    /** The error code. */
    private String error;

    /** The error description. */
    private String errorDescription;

    /**
     * Get the error code.
     * 
     * @return error code if set, otherwise null.
     */
    public String getErrorCode() {
        return error;
    }

    /**
     * Set the error code.
     * 
     * @param code the code for error.
     */
    public void setErrorCode(String code) {
        this.error = code;
    }

    /**
     * Get the error description.
     * 
     * @return error description if set, otherwise null.
     */
    public String getErrorDescription() {
        return errorDescription;
    }

    /**
     * Set the error description.
     * 
     * @param description the description of error.
     */
    public void setErrorDescription(String description) {
        this.errorDescription = description;
    }

}
