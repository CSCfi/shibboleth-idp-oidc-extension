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

import java.net.URI;
import java.util.Date;
import javax.annotation.Nullable;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.messaging.context.BaseContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

/**
 * Subcontext carrying information to form authentication/token/userinfo response for relying party. This context
 * appears as a subcontext of the {@link org.opensaml.messaging.context.MessageContext}.
 */
public class OIDCAuthenticationResponseContext extends BaseContext {

    /** The id token formed. */
    @Nullable
    private IDTokenClaimsSet idToken;

    /** The user info formed. */
    @Nullable
    private UserInfo userInfo;

    /** The signed/encrypted id token / user info response formed. */
    @Nullable
    private JWT processedToken;

    /** the acr used in response. **/
    @Nullable
    private ACR acr;

    /** validated redirect uri. */
    @Nullable
    private URI redirectURI;

    /** Authentication time of the end user. */
    private Date authTime;

    /** Validated scope values. */
    private Scope requestedScope;

    /** Requested sub value. */
    @Nullable
    private String requestedSubject;

    /** Subject generated for response. Value is set to sub claim. */
    private String subject;

    /** Authorization code. */
    @Nullable
    private AuthorizationCode authorizationCode;

    /** Access token. */
    @Nullable
    private AccessToken accessToken;

    /** Refresh token. */
    @Nullable
    private RefreshToken refreshToken;

    /** Token (authz code, access token) claims. */
    @Nullable
    private TokenClaimsSet tokenClaims;

    /** Requested claims. */
    @Nullable
    private ClaimsRequest requestedClaims;

    /**
     * Get requested claims.
     * 
     * @return requested claims
     */
    @Nullable
    public ClaimsRequest getRequestedClaims() {
        return requestedClaims;
    }

    /**
     * Set requested claims.
     * 
     * @param claims requested claims
     */
    public void setRequestedClaims(@Nullable ClaimsRequest claims) {
        requestedClaims = claims;
    }

    /**
     * Get token claims.
     * 
     * @return token claims
     */
    public TokenClaimsSet getTokenClaimsSet() {
        return tokenClaims;
    }

    /**
     * Set token claims.
     * 
     * @param claims token claims
     */
    public void setTokenClaimsSet(TokenClaimsSet claims) {
        tokenClaims = claims;
    }

    /**
     * Get authorization code.
     * 
     * @return authorization code
     */
    @Nullable
    public AuthorizationCode getAuthorizationCode() {
        return authorizationCode;
    }

    /**
     * Set authorization code.
     * 
     * @param code String to form authorization code
     */
    public void setAuthorizationCode(@Nullable String code) {
        authorizationCode = code == null ? null : new AuthorizationCode(code);
    }

    /**
     * Get access token.
     * 
     * @return access token
     */
    @Nullable
    public AccessToken getAccessToken() {
        return accessToken;
    }

    /**
     * Set access token.
     * 
     * @param token String to form access token
     * @param lifeTime lifetime of the access token is seconds.
     */
    public void setAccessToken(@Nullable String token, long lifeTime) {
        accessToken = token == null ? null : new BearerAccessToken(token, lifeTime, null);
    }

    /**
     * Get refresh token.
     * 
     * @return refresh token
     */
    @Nullable
    public RefreshToken getRefreshToken() {
        return refreshToken;
    }

    /**
     * Set refresh token.
     * 
     * @param token String to form refresh token
     */
    public void setRefreshToken(@Nullable String token) {
        refreshToken = token == null ? null : new RefreshToken(token);
    }

    /**
     * Gets requested sub value.
     * 
     * @return requested sub value
     */
    @Nullable
    public String getRequestedSubject() {
        return requestedSubject;
    }

    /**
     * Set requested sub value.
     * 
     * @param sub requested sub value.
     */
    public void setRequestedSubject(@Nullable String sub) {
        this.requestedSubject = sub;
    }

    /**
     * Gets Name ID generated for response.
     * 
     * @return Name ID generated for response
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Sets generated subject for the response.
     * 
     * @param generated subject for the response
     */
    public void setSubject(String generatedSubject) {
        subject = generatedSubject;
    }

    /**
     * Get validated scope values.
     * 
     * @return validated scope values
     */
    public Scope getScope() {
        return requestedScope;
    }

    /**
     * Set validated scope values.
     * 
     * @param scope scope values
     */
    public void setScope(Scope scope) {
        requestedScope = scope;
    }

    /**
     * Authentication time of the end user.
     * 
     * @return authentication time of the end user. null if has not been set.
     */
    @Nullable
    public Date getAuthTime() {
        return authTime;
    }

    /**
     * Set authentication time of the end user in millis from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
     * 
     * @param time authentication time.
     */
    public void setAuthTime(long time) {
        authTime = new Date(time);
    }

    /**
     * Returns a validated redirect uri for the response.
     * 
     * @return redirect uri.
     */
    @Nullable
    public URI getRedirectURI() {
        return redirectURI;
    }

    /**
     * Sets a validated redirect uri for the response.
     * 
     * @param uri validated redirect uri for the response
     */
    public void setRedirectURI(@Nullable URI uri) {
        redirectURI = uri;
    }

    /**
     * Returns the acr meant for response.
     * 
     * @return acr
     */
    @Nullable
    public ACR getAcr() {
        return acr;
    }

    /**
     * Set acr for response.
     * 
     * @param acrValue for response.
     */
    public void setAcr(@Nullable String acrValue) {
        if (acrValue != null) {
            acr = new ACR(acrValue);

        } else {
            acr = null;
        }
    }

    /**
     * Get the id token.
     * 
     * @return The id token.
     */
    @Nullable
    public IDTokenClaimsSet getIDToken() {
        return idToken;
    }

    /**
     * Set the id token.
     * 
     * @param token The id token.
     */
    public void setIDToken(@Nullable IDTokenClaimsSet token) {
        idToken = token;
    }

    /**
     * Get the user info.
     * 
     * @return The user info.
     */
    @Nullable
    public UserInfo getUserInfo() {
        return userInfo;
    }

    /**
     * Set the user info.
     * 
     * @param info The user info.
     */
    public void setUserInfo(@Nullable UserInfo info) {
        userInfo = info;
    }

    /**
     * Get the signed/encrypted id token / user info response.
     * 
     * @return The signed id token / user info response
     */
    @Nullable
    public JWT getProcessedToken() {
        return processedToken;
    }

    /**
     * Set the signed/encrypted id token / user info response.
     * 
     * @param token The signed id token / user info response
     */
    public void setProcessedToken(@Nullable JWT token) {
        processedToken = token;
    }
}