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

package org.geant.idpextension.oidc.profile.impl;

import java.io.IOException;
import java.text.ParseException;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.util.EntityUtils;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.opensaml.security.httpclient.HttpClientSecuritySupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jwt.JWTParser;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that stored request object to {@link OidcResponseContext}. The request
 * object may be given by value with request parameter or by reference with
 * request_uri parameter.
 */

@SuppressWarnings("rawtypes")
public class SetRequestObjectToResponseContext extends AbstractOIDCAuthenticationResponseAction {

	/** Class logger. */
	@Nonnull
	private Logger log = LoggerFactory.getLogger(SetRequestObjectToResponseContext.class);

	/** HTTP Client used to post the data. */
	@NonnullAfterInit
	private HttpClient httpClient;

	/** HTTP client security parameters. */
	@Nullable
	private HttpClientSecurityParameters httpClientSecurityParameters;

	/**
	 * Set the {@link HttpClient} to use.
	 * 
	 * @param client
	 *            client to use
	 */
	public void setHttpClient(@Nonnull final HttpClient client) {
		httpClient = Constraint.isNotNull(client, "HttpClient cannot be null");
	}

	/**
	 * Set the optional client security parameters.
	 * 
	 * @param params
	 *            the new client security parameters
	 */
	public void setHttpClientSecurityParameters(@Nullable final HttpClientSecurityParameters params) {
		httpClientSecurityParameters = params;
	}

	/**
	 * Build the {@link HttpClientContext} instance to be used by the HttpClient.
	 * 
	 * @param request
	 *            the HTTP client request
	 * @return the client context instance
	 */
	@Nonnull
	private HttpClientContext buildHttpContext(@Nonnull final HttpUriRequest request) {
		final HttpClientContext clientContext = HttpClientContext.create();
		HttpClientSecuritySupport.marshalSecurityParameters(clientContext, httpClientSecurityParameters, false);
		HttpClientSecuritySupport.addDefaultTLSTrustEngineCriteria(clientContext, request);
		return clientContext;
	}
	
	/** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        Constraint.isNotNull(httpClient, "Httpclient cannot be null");
    }

	/** {@inheritDoc} */
	@Override
	protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
		if (!super.doPreExecute(profileRequestContext)) {
			return false;
		}
		if (!getAuthenticationRequest().specifiesRequestObject()) {
			log.debug("{} No request_uri or request by value, nothing to do", getLogPrefix());
			return false;
		}
		if (getAuthenticationRequest().getRequestObject() != null
				&& getAuthenticationRequest().getRequestURI() != null) {
			log.error("{} request_uri and request object cannot be both set", getLogPrefix());
			ActionSupport.buildEvent(profileRequestContext, OidcEventIds.REQUEST_OBJECT_AND_URI);
			return false;
		}
		return true;
	}

	/** {@inheritDoc} */
	@Override
	protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
		if (getAuthenticationRequest().getRequestObject() != null) {
			getOidcResponseContext().setRequestObject(getAuthenticationRequest().getRequestObject());
			log.debug("{} Request object {} by value stored to oidc response context", getLogPrefix(),
					getOidcResponseContext().getRequestObject().serialize());
			return;
		}
		final HttpGet httpRequest = new HttpGet(getAuthenticationRequest().getRequestURI());
		final HttpClientContext httpContext = buildHttpContext(httpRequest);
		try {
			final HttpResponse response = httpClient.execute(httpRequest, httpContext);
			HttpClientSecuritySupport.checkTLSCredentialEvaluated(httpContext, httpRequest.getURI().getScheme());
			if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
				String requestObject = EntityUtils.toString(response.getEntity());
				try {
					getOidcResponseContext().setRequestObject(JWTParser.parse(requestObject));
					log.debug("{} Request object {} by reference stored to oidc response context", getLogPrefix(),
							getOidcResponseContext().getRequestObject().serialize());
					return;
				} catch (ParseException e) {
					log.error("{} Unable to parse request object from request_uri, {}", getLogPrefix(), e.getMessage());
					ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_URI);
					return;
				}
			} else {
				log.error("{} Unable to get request object from request_uri, HTTP status {}", getLogPrefix(),
						response.getStatusLine().getStatusCode());
				ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_URI);
				return;
			}
		} catch (IOException e) {
			log.error("{} Unable to get request object from request_uri, {}", getLogPrefix(), e.getMessage());
			ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_URI);
			return;
		}
	}
}
