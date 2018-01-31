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

package org.geant.idpextension.oidc.token.support;

import java.util.Date;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;
import java.text.ParseException;

/** Class wrapping claims set for access token. */
public final class AccessTokenClaimsSet extends AbstractTokenClaimsSet {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AccessTokenClaimsSet.class);

    /** Value of authorize code claims set type. */
    public static final String VALUE_TYPE_AT = "at";

    /**
     * Constructor for access token claims set.
     * 
     * @param authorizeCode
     *            Authorize Code this token is based on. Must not be NULL.
     * @param iat
     *            Issue time of the token. Must not be NULL.
     * @param exp
     *            Expiration time of the token. Must not be NULL.
     * @throws RuntimeException
     *             if called with non allowed null parameters
     */
    public AccessTokenClaimsSet(@Nonnull AuthorizeCodeClaimsSet authorizeCode, @Nonnull Date iat, @Nonnull Date exp) {
        super(VALUE_TYPE_AT, authorizeCode.getID(), authorizeCode.getClientID(),
                authorizeCode.getClaimsSet().getIssuer(), authorizeCode.getClaimsSet().getSubject(),
                new ACR(authorizeCode.getACR()), iat, exp, authorizeCode.getNonce(),
                authorizeCode.getAuthenticationTime(), authorizeCode.getRedirectURI(), authorizeCode.getScope(),
                authorizeCode.getClaimsRequest());
    }

    /**
     * Private constructor for the parser.
     * 
     * @param set
     *            authorize code claims set
     */
    private AccessTokenClaimsSet(JWTClaimsSet accessTokenClaimsSet) {
        tokenClaimsSet = accessTokenClaimsSet;
    }

    /**
     * Parses access token from string (JSON)
     * 
     * @param accessTokenClaimsSet
     *            JSON String representation of the code
     * @return AuthorizeCodeClaimsSet instance if parsing is successful.
     * @throws ParseException
     *             if parsing fails for example due to incompatible types.
     */
    public static AccessTokenClaimsSet parse(String accessTokenClaimsSet) throws ParseException {
        JWTClaimsSet atClaimsSet = JWTClaimsSet.parse(accessTokenClaimsSet);
        // Throws exception if parsing result is not expected one.
        verifyParsedClaims(VALUE_TYPE_AT, atClaimsSet);
        return new AccessTokenClaimsSet(atClaimsSet);
    }

    /**
     * Parses access token from sealed access token
     * 
     * @param wrappedAccessToken
     *            wrapped access token
     * @param dataSealer
     *            sealer to unwrap the access token
     * @return
     * @throws ParseException
     *             is thrown if unwrapped access token is not understood
     * @throws DataSealerException
     *             is thrown if unwrapping fails
     */
    public static AccessTokenClaimsSet parse(@Nonnull String wrappedAccessToken, @Nonnull DataSealer dataSealer)
            throws ParseException, DataSealerException {
        return parse(dataSealer.unwrap(wrappedAccessToken));
    }

}
