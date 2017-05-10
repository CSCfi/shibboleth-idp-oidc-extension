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

import org.opensaml.messaging.context.BaseContext;

import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * Subcontext carrying information on response formed for relying party. This
 * context appears as a subcontext of the
 * {@link org.opensaml.messaging.context.MessageContext}.
 */
public class OIDCResponseContext extends BaseContext {

	/** error code. */
	private String error;

	/** error description. */
	private String errorDescription;

	/** The id token formed. */
	@Nullable
	private IDTokenClaimsSet idToken;

	/** the acr used in response. **/
	@Nullable
	private ACR acr;

	/** validated redirect uri. */
	@Nullable
	private URI redirectURI;

	/** Authentication time of the end user. */
	private Date auth_time;

	/** Expiration time of the id token. */
	private Date exp;

	/**
	 * Get error code.
	 * 
	 * @return error code if set, otherwise null
	 */
	public String getErrorCode() {
		return error;
	}

	/**
	 * Set error code.
	 * 
	 * @param code
	 *            for error
	 */
	public void setErrorCode(String code) {
		this.error = code;
	}

	/**
	 * Get error description.
	 * 
	 * @return error description if set, otherwise null
	 */
	public String getErrorDescription() {
		return errorDescription;
	}

	/**
	 * Set error description.
	 * 
	 * @param description
	 *            of error
	 */
	public void setErrorDescription(String description) {
		this.errorDescription = description;
	}

	/**
	 * Authentication time of the end user.
	 * 
	 * @return authentication time of the end user. null if has not been set.
	 */
	@Nullable
	public Date getAuthTime() {
		return auth_time;
	}

	/**
	 * Set authentication time of the end user in millis from 1970-01-01T0:0:0Z
	 * as measured in UTC until the date/time.
	 * 
	 * @param authTime
	 *            authentication time.
	 */
	public void setAuthTime(long authTime) {
		this.auth_time = new Date(authTime);
	}

	/**
	 * Expiration time of the id token.
	 * 
	 * @return expiration time of the id token. null if has not been set.
	 */
	@Nullable
	public Date getExp() {
		return exp;
	}

	/**
	 * Set expiration time of the id token in millis from 1970-01-01T0:0:0Z as
	 * measured in UTC until the date/time.
	 * 
	 * @param authTime
	 *            authentication time.
	 */
	public void setExp(long expTime) {
		this.exp = new Date(expTime);
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
	 * @param redirectURI
	 */
	public void setRedirectURI(@Nullable URI redirectURI) {
		this.redirectURI = redirectURI;
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
	 * @param acrValue
	 *            for response.
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
	 * @return The client information.
	 */
	@Nullable
	public IDTokenClaimsSet getIDToken() {
		return idToken;
	}

	/**
	 * Set the id token.
	 * 
	 * @param token
	 *            The id token.
	 */
	public void setIDToken(@Nullable IDTokenClaimsSet token) {
		idToken = token;
	}
}