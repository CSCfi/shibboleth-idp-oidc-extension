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

package org.geant.idpextension.oidc.profile.impl;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.util.EntityUtils;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.opensaml.security.httpclient.HttpClientSecuritySupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.rp.ApplicationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * <p>The action that verifies the redirect_uris from the request. At least one must exist. Also, if 
 * sector_identifier_uri has been defined in the request, all the redirect_uris must exists from the contents behind
 * the URI.</p>
 * 
 * <p>The specification defines the following for <pre>application_type</pre>:</p>
 * 
 * <p>Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris;
 * they MUST NOT 
 * use localhost as the hostname. Native Clients MUST only register redirect_uris using custom URI schemes or URLs 
 * using the http: scheme with localhost as the hostname. Authorization Servers MAY place additional constraints on 
 * Native Clients. Authorization Servers MAY reject Redirection URI values using the http scheme, other than the 
 * localhost case for Native Clients. </p>
 */
@SuppressWarnings("rawtypes")
public class CheckRedirectURIs extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(CheckRedirectURIs.class);
    
    /** The OIDCClientRegistrationRequest to check redirect URIs from. */
    @Nullable private OIDCClientRegistrationRequest request;

    /** The {@link HttpClient} to use. */
    @NonnullAfterInit private HttpClient httpClient;
    
    /** HTTP client security parameters. */
    @Nullable private HttpClientSecurityParameters httpClientSecurityParameters;

    /** Constructor. */
    public CheckRedirectURIs() {
        super();
    }
    
    /**
     * Set the {@link HttpClient} to use.
     * 
     * @param client client to use
     */
    public void setHttpClient(@Nonnull final HttpClient client) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        httpClient = Constraint.isNotNull(client, "HttpClient cannot be null");
    }

    /**
     * Set the optional client security parameters.
     * 
     * @param params the new client security parameters
     */
    public void setHttpClientSecurityParameters(@Nullable final HttpClientSecurityParameters params) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        httpClientSecurityParameters = params;
    }

    /** {@inheritDoc} */
    public void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (httpClient == null) {
            throw new ComponentInitializationException(getLogPrefix() + " HttpClient cannot be null");
        }
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        if (profileRequestContext.getInboundMessageContext() == null) {
            log.debug("{} No inbound message context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;            
        }
        Object message = profileRequestContext.getInboundMessageContext().getMessage();
        if (message == null || !(message instanceof OIDCClientRegistrationRequest)) {
            log.debug("{} No inbound message associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;                        
        }
        request = (OIDCClientRegistrationRequest) message;
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final OIDCClientMetadata metadata = request.getOIDCClientMetadata();
        if (metadata == null) {
            log.warn("{} No client metadata found in the request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        final Set<URI> redirectURIs = metadata.getRedirectionURIs();
        if (redirectURIs == null || redirectURIs.isEmpty()) {
            log.warn("{} No redirection URIs found in the request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.MISSING_REDIRECT_URIS);
            return;
        }
        final URI sectorIdUri = metadata.getSectorIDURI();
        if (sectorIdUri != null) {
            log.debug("{} Found sector_identifier_uri {}", getLogPrefix(), sectorIdUri);
            if (!sectorIdUri.getScheme().equals("https")) {
                log.warn("{} Invalid sector_identifier_uri scheme {}", getLogPrefix(), sectorIdUri.getScheme());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;
            }
            if (!verifySectorIdUri(sectorIdUri, redirectURIs)) {
                log.warn("{} All redirect URIs are not found from sector_identifier_uri", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REDIRECT_URIS);
                return;                
            }
        }
        final ApplicationType applicationType = metadata.getApplicationType();
        if (applicationType == null || applicationType.equals(ApplicationType.WEB)) {
            final Set<GrantType> grantTypes = metadata.getGrantTypes();
            // if implicit, only https
            if (grantTypes != null && grantTypes.contains(GrantType.IMPLICIT) 
                    && !checkScheme(redirectURIs, "https")) {
                log.warn("{} Only https-scheme is allowed for implicit flow", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REDIRECT_URIS);
                return;
            }
            // no localhost as the hostname
            if (checkForbiddenHostname(redirectURIs, "localhost")) {
                log.warn("{} localhost as the hostname in the redirect URI for a Web app", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REDIRECT_URIS);
                return;
            }
        } else {
            // native application
            // http://localhost or custom scheme
            if (checkForbiddenScheme(redirectURIs, "https")) {
                log.warn("{} https-scheme is not allowed for a native application", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REDIRECT_URIS);
                return;                                    
            }
            for (final URI redirectUri : redirectURIs) {
                final String scheme = redirectUri.getScheme();
                if (scheme.equalsIgnoreCase("http") && !redirectUri.getHost().equalsIgnoreCase("localhost")) {
                    log.warn("{} http-scheme is only allowed to localhost for a native application", getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REDIRECT_URIS);
                    return;                                        
                }
                log.debug("{} Accepting a redirect URI {} for a native application", getLogPrefix(), redirectUri);
            }
        }
        //TODO: should the URIs be checked against black/white-lists?
        log.debug("{} Redirect URIs ({}) checked", getLogPrefix(), redirectURIs.size());
    }
    
    /**
     * Verifies that all the given redirect URIs are found from the contents of the given sector identifier URI.
     * @param sectorIdUri The sector identifier URI.
     * @param redirectURIs The redirect URIs to be verified.
     * @return true if redirect URIs were found from the contents, false otherwise or if the contents could not be
     * fetched.
     */
    protected boolean verifySectorIdUri(final URI sectorIdUri, final Set<URI> redirectURIs) {
        final HttpResponse response;
        try {
            final HttpUriRequest get = RequestBuilder.get().setUri(sectorIdUri).build();
            final HttpClientContext clientContext = HttpClientContext.create();
            HttpClientSecuritySupport.marshalSecurityParameters(clientContext, httpClientSecurityParameters, true);
            HttpClientSecuritySupport.addDefaultTLSTrustEngineCriteria(clientContext, get);
            response = httpClient.execute(get, clientContext);
            HttpClientSecuritySupport.checkTLSCredentialEvaluated(clientContext, get.getURI().getScheme());
        } catch (Exception e) {
            log.error("{} Could not get the sector_identifier_uri contents from {}", getLogPrefix(), sectorIdUri, e);
            return false;
        }
        if (response == null) {
            log.error("{} Could not get the sector_identifier_uri contents from {}", getLogPrefix(), sectorIdUri);
            return false;
        }
        final String output;
        try {
            output = EntityUtils.toString(response.getEntity(), "UTF-8");
        } catch (ParseException | IOException e) {
            log.error("{} Could not parse the sector_identifier_uri contents from {}", getLogPrefix(), sectorIdUri);
            return false;
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
        log.trace("{} Fetched the following response body: {}", getLogPrefix(), output);
        final Type listType = new TypeToken<ArrayList<URI>>(){}.getType();
        final List<URI> parsedUris;
        try {
            parsedUris = new Gson().fromJson(output, listType);
        } catch (JsonSyntaxException e) {
            log.error("{} Could not parse the sector_identifier_uri contents from {}", getLogPrefix(), sectorIdUri);
            return false;            
        }
        if (parsedUris == null) {
            log.error("{} sector_identifier_uris contents is empty, no URLs included: {}", getLogPrefix(), output);
            return false;
        }
        for (final URI redirectUri : redirectURIs) {
            if (!parsedUris.contains(redirectUri)) {
                log.error("{} Redirect URI {} was not found from the sector_identifier_uris", getLogPrefix(), 
                        redirectUri);
                return false;
            }
            log.trace("{} Redirect URI was validated against the sector_identifier_uris", getLogPrefix());
        }
        return true;
    }

    /**
     * Checks whether a given scheme is used by every item in the given set of URIs.
     * @param redirectURIs The URIs to check from.
     * @param scheme The scheme to check.
     * @return true if scheme was used in all URIs, false otherwise.
     */
    protected boolean checkScheme(final Set<URI> redirectURIs, final String scheme) {
        for (final URI redirectUri : redirectURIs) {
            if (!redirectUri.getScheme().equals(scheme)) {
                log.trace("{} Found '{}' as the scheme in the redirect URI, all should be {}", getLogPrefix(), 
                        redirectUri.getScheme(), scheme);
                return false;
            }
        }
        return true;
    }
    
    /**
     * Checks whether a given scheme is found from the given set of URIs.
     * @param redirectURIs The URIs to check from.
     * @param scheme The scheme to check.
     * @return true if scheme was found once or more, false otherwise.
     */
    protected boolean checkForbiddenScheme(final Set<URI> redirectURIs, final String scheme) {
        for (final URI redirectUri : redirectURIs) {
            if (redirectUri.getScheme().equals(scheme)) {
                log.trace("{} Found forbidden '{}' as the scheme in the redirect URI {}", getLogPrefix(), 
                        scheme, redirectUri);
                return true;
            }
        }
        return false;
    }
    
    /**
     * Checks whether a given hostname is found from the given set of URIs.
     * @param redirectURIs The URIs to check from.
     * @param hostname The hostname to check.
     * @return true if hostname was found once or more, false otherwise.
     */
    protected boolean checkForbiddenHostname(final Set<URI> redirectURIs, final String hostname) {
        for (final URI redirectUri : redirectURIs) {
            if (redirectUri.getHost().equalsIgnoreCase(hostname)) {
                log.trace("{} Found forbidden {} as the hostname in the redirect URIs", getLogPrefix(), hostname);
                return true;
            }
        }
        return false;
    }
}
