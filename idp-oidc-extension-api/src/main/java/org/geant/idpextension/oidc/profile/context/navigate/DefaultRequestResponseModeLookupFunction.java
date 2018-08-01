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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.text.ParseException;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

/**
 * A function that returns copy of the response mode of the request via a lookup function. This default lookup locates
 * response mode from oidc authentication request if available. If information is not available, null is returned. If
 * there is response mode in request object it is used instead of response_mode parameter.
 */
public class DefaultRequestResponseModeLookupFunction
        extends AbstractAuthenticationRequestLookupFunction<ResponseMode> {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DefaultRequestResponseModeLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    ResponseMode doLookup(@Nonnull AuthenticationRequest req) {
        JWT requestObject = req.getRequestObject();
        try {
            if (requestObject != null && requestObject.getJWTClaimsSet().getClaim("response_mode") != null) {
                Object rMode = requestObject.getJWTClaimsSet().getClaim("response_mode");
                if (rMode instanceof String) {
                    return new ResponseMode((String) rMode);
                } else {
                    log.error("response_mode claim is not of expected type");
                    return null;
                }
            }
        } catch (ParseException e) {
            log.error("Unable to parse response mode from request object response_mode value");
            return null;
        }
        if (req.getResponseMode() == null) {
            return null;
        }
        ResponseMode responseMode = new ResponseMode(req.getResponseMode().getValue());
        return responseMode;
    }
}