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
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;

import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.DataSealerException;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import java.net.URI;
import java.text.ParseException;

/** Class wrapping claims set for authorize code. */
public final class AuthorizeCodeClaimsSet {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AuthorizeCodeClaimsSet.class);

    /** Claims set for the claim. */
    private JWTClaimsSet authzCodeClaims;

    /** Value of authorize code claims set type. */
    public static final String VALUE_TYPE_AC = "ac";

    /** OP issuer. */
    public static final String KEY_ISSUER = "iss";

    /** User principal representing authenticated user. */
    public static final String KEY_USER_PRINCIPAL = "sub";

    /**
     * Client Id of the rp the code is generated for. Type is string array (aud).
     */
    public static final String KEY_CLIENTID = "aud";

    /** Expiration time of the authorize code. */
    public static final String KEY_EXPIRATION_TIME = "exp";

    /** Issue time of the authorize code. */
    public static final String KEY_ISSUED_AT = "iat";

    /** Unique identifier for the authorization code. */
    public static final String KEY_AC_ID = "jti";

    /** Type of the token. */
    public static final String KEY_TYPE = "type";

    /**
     * Authentication context class reference value of the performed authentication.
     */
    public static final String KEY_ACR = "acr";

    /** Nonce of the original authentication request. */
    public static final String KEY_NONCE = "nonce";

    /** Authentication time of the performed authentication. */
    public static final String KEY_AUTH_TIME = "auth_time";

    /** Redirect uri of the original authentication request. */
    public static final String KEY_REDIRECT_URI = "redirect_uri";

    /** Scope of the original authentication request. */
    public static final String KEY_SCOPE = "scope";

    /** Claims request of the original authentication request. */
    public static final String KEY_CLAIMS = "claims";

    /**
     * Constructor for authorize code claims set.
     * 
     * @param idGenerator
     *            Generator for pseudo unique identifier for the code. Must not be
     *            NULL.
     * @param clientID
     *            Client Id of the rp. Must not be NULL.
     * @param issuer
     *            OP issuer value. Must not be NULL.
     * @param userPrincipal
     *            User Principal of the authenticated user. Must not be NULL.
     * @param acr
     *            Authentication context class reference value of the
     *            authentication. Must not be NULL.
     * @param iat
     *            Issue time of the authorize code. Must not be NULL.
     * @param exp
     *            Expiration time of the authorize code. Must not be NULL.
     * @param nonce
     *            Nonce of the authentication request. May be NULL.
     * @param authTime
     *            Authentication time of the user. Must not be NULL.
     * @param redirect_uri
     *            Validated redirect URI of the authentication request. Must not be
     *            NULL.
     * @param scope
     *            Scope of the authentication request. Must not be NULL.
     * @param claims
     *            Claims request of the authentication request. May be NULL.
     * @throws RuntimeException
     *             if called with nnonallowed ull parameters
     */
    public AuthorizeCodeClaimsSet(@Nonnull IdentifierGenerationStrategy idGenerator, @Nonnull ClientID clientID,
            @Nonnull String issuer, @Nonnull String userPrincipal, @Nonnull ACR acr, @Nonnull Date iat,
            @Nonnull Date exp, @Nullable Nonce nonce, @Nonnull Date authTime, @Nonnull URI redirect_uri,
            @Nonnull Scope scope, @Nonnull ClaimsRequest claims) {
        if (idGenerator == null || clientID == null || issuer == null || userPrincipal == null || acr == null
                || iat == null || exp == null || authTime == null || redirect_uri == null || scope == null) {
            throw new RuntimeException("Invalid parameters, programming error");
        }
        authzCodeClaims = new JWTClaimsSet.Builder()
                // States this is authorization code claims set.
                .claim(KEY_TYPE, VALUE_TYPE_AC).jwtID(idGenerator.generateIdentifier()).audience(clientID.getValue())
                .issuer(issuer).subject(userPrincipal).claim("acr", acr.getValue()).issueTime(iat).expirationTime(exp)
                .claim(KEY_NONCE, nonce == null ? null : nonce.getValue()).claim("auth_time", authTime)
                .claim(KEY_REDIRECT_URI, redirect_uri.toString()).claim(KEY_SCOPE, scope.toString())
                .claim(KEY_CLAIMS, claims == null ? null : claims.toJSONObject()).build();
    }

    /**
     * Private constructor for the parser.
     * 
     * @param set
     *            authorize code claims set
     */
    private AuthorizeCodeClaimsSet(JWTClaimsSet authzCodeClaimsSet) {
        authzCodeClaims = authzCodeClaimsSet;
    }

    /**
     * Parses authz code from string (JSON)
     * 
     * @param authorizeCodeClaimsSet
     *            JSON String representation of the code
     * @return AuthorizeCodeClaimsSet instance if parsing is successful.
     * @throws ParseException
     *             if parsing fails for example due to incompatible types.
     */
    public static AuthorizeCodeClaimsSet parse(String authorizeCodeClaimsSet) throws ParseException {
        JWTClaimsSet acClaimsSet = JWTClaimsSet.parse(authorizeCodeClaimsSet);
        // Check existence and type of mandatory fields and values
        if (!VALUE_TYPE_AC.equals(acClaimsSet.getClaims().get(KEY_TYPE))) {
            throw new ParseException("claim type must have value ac", 0);
        }
        //Mandatory fields
        if (acClaimsSet.getStringClaim(KEY_ISSUER) == null) {
            throw new ParseException("claim iss must exist and not be null", 0);
        }
        if (acClaimsSet.getStringClaim(KEY_USER_PRINCIPAL) == null) {
            throw new ParseException("claim sub must exist and not be null", 0);
        }
        if (acClaimsSet.getStringArrayClaim(KEY_CLIENTID) == null) {
            throw new ParseException("claim aud must exist and not be null", 0);
        }
        if (acClaimsSet.getDateClaim(KEY_EXPIRATION_TIME) == null) {
            throw new ParseException("claim exp must exist and not be null", 0);
        }
        if (acClaimsSet.getDateClaim(KEY_ISSUED_AT) == null) {
            throw new ParseException("claim iat must exist and not be null", 0);
        }
        if (acClaimsSet.getStringClaim(KEY_AC_ID) == null) {
            throw new ParseException("claim jti must exist and not be null", 0);
        }
        if (acClaimsSet.getStringClaim(KEY_ACR) == null) {
            throw new ParseException("claim acr must exist and not be null", 0);
        }
        if (acClaimsSet.getDateClaim(KEY_AUTH_TIME) == null) {
            throw new ParseException("claim auth_time must exist and not be null", 0);
        }
        if (acClaimsSet.getStringClaim(KEY_REDIRECT_URI) == null) {
            throw new ParseException("claim redirect_uri must exist and not be null", 0);
        }
        if (acClaimsSet.getStringClaim(KEY_SCOPE) == null) {
            throw new ParseException("claim scope must exist and not be null", 0);
        }
        //Voluntary fields
        if (acClaimsSet.getClaims().containsKey(KEY_CLAIMS)) {
            acClaimsSet.getJSONObjectClaim(KEY_CLAIMS);
        }
        if (acClaimsSet.getClaims().containsKey(KEY_NONCE)) {
            acClaimsSet.getStringClaim(KEY_NONCE);
        }
        return new AuthorizeCodeClaimsSet(acClaimsSet);
    }

    /**
     * Parses authz code from sealed authorization code
     * 
     * @param wrappedAuthCode
     *            wrapped code
     * @param dataSealer
     *            sealer to unwrap the code
     * @return
     * @throws ParseException
     *             is thrown if unwrapped code is not understood
     * @throws DataSealerException
     *             is thrown if unwrapping fails
     */
    public static AuthorizeCodeClaimsSet parse(@Nonnull String wrappedAuthCode, @Nonnull DataSealer dataSealer)
            throws ParseException, DataSealerException {
        return parse(dataSealer.unwrap(wrappedAuthCode));
    }

    /**
     * Serialize the authz code as JSON String.
     * 
     * @return authz code as JSON String
     */
    public String serialize() {
        log.debug("Serializing to {}", authzCodeClaims.toJSONObject().toJSONString());
        return authzCodeClaims.toJSONObject().toJSONString();
    }

    /**
     * Serialize the authz code as JSON String wrapped with sealer.
     * 
     * @param dataSealer
     *            data sealer to wrap the JSON serialization
     * @return authz code as JSON String wrapped with sealer
     * @throws DataSealerException
     *             is thrown if unwrapping fails
     */
    public String serialize(@Nonnull DataSealer dataSealer) throws DataSealerException {
        String wrapped = dataSealer.wrap(serialize(), authzCodeClaims.getExpirationTime().getTime());
        log.debug("Wrapped to {}", wrapped);
        return wrapped;
    }

    /**
     * Get the authorization code claims set.
     * 
     * @return authorization code claims set
     */
    @Nonnull
    public JWTClaimsSet getClaimsSet() {
        return authzCodeClaims;
    }

    /**
     * Check if the authz code is expired.
     * 
     * @return true if the code is expired, otherwise false.
     */
    public boolean isExpired() {
        return authzCodeClaims.getExpirationTime().before(new Date());
    }

    /**
     * Get expiration time of the authz code.
     * 
     * @return expiration time of the authz code.
     */
    @Nonnull
    public Date getExp() {
        return authzCodeClaims.getExpirationTime();
    }

    /**
     * Get redirect uri of the request.
     * 
     * @return redirect uri of the request, null if not located.
     */
    @Nonnull
    public URI getRedirectURI() {
        try {
            return URI.create(authzCodeClaims.getStringClaim(KEY_REDIRECT_URI));
        } catch (ParseException e) {
            log.error("error parsing redirect uri from auth code", e.getMessage());
        }
        // should never happen, programming error.
        return null;
    }

    /**
     * Get acr of the performed authentication.
     * 
     * @return acr of the performed authentication.
     */
    @Nonnull
    public String getACR() {
        return (String) authzCodeClaims.getClaim(KEY_ACR);
    }

    /**
     * Get auth time of the user.
     * 
     * @return auth time of the user.
     */
    @Nonnull
    public Date getAuthenticationTime() {
        try {
            return authzCodeClaims.getDateClaim(KEY_AUTH_TIME);
        } catch (ParseException e) {
            log.error("Error parsing auth time {}", authzCodeClaims.getClaim(KEY_AUTH_TIME));
            // should never happen, programming error.
            return null;
        }
    }

    /**
     * Get copy of the nonce in authentication request.
     * 
     * @return copy of the nonce in authentication request.
     */
    @Nonnull
    public Nonce getNonce() {
        if (authzCodeClaims.getClaim(KEY_NONCE) == null) {
            return null;
        }
        return new Nonce((String) authzCodeClaims.getClaim(KEY_NONCE));
    }

    /**
     * Get copy of the claims request in authentication request.
     * 
     * @return copy of the claims request in authentication request, null if not
     *         existing.
     */
    @Nullable
    public ClaimsRequest getClaimsRequest() {
        if (authzCodeClaims.getClaim(KEY_CLAIMS) == null) {
            return null;
        }
        try {
            return ClaimsRequest.parse((authzCodeClaims.getJSONObjectClaim(KEY_CLAIMS)));
        } catch (ParseException e) {
            log.error("Error parsing claims request {}", authzCodeClaims.getClaim(KEY_CLAIMS));
            return null;
        }
    }

    /**
     * Get copy of the scope in authentication request.
     * 
     * @return copy of the scope in authentication request.
     */
    @Nonnull
    public Scope getScope() {
        try {
            return Scope.parse((authzCodeClaims.getStringClaim(KEY_SCOPE)));
        } catch (ParseException e) {
            log.error("Error parsing scope in request {}", authzCodeClaims.getClaim(KEY_SCOPE));
            // should never happen, programming error.
            return null;
        }
    }
    
    /**
     * Get the id of the authz code.
     * @return id of the authz code
     */
    @Nonnull
    public String getID() {
        return authzCodeClaims.getJWTID();
    }
    
}
