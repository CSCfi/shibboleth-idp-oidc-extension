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
import java.lang.reflect.Type;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.util.EntityUtils;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.rp.ApplicationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
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

    /** The builder for the {@link HttpClient}s. */
    private HttpClientBuilder clientBuilder;

    /** Constructor. */
    public CheckRedirectURIs() {
        super();
        clientBuilder = new HttpClientBuilder();
    }
    
    /**
     * Set the builder for the {@link HttpClient}s.
     * @param builder The builder for the {@link HttpClient}s.
     */
    public void setHttpClientBuilder(final HttpClientBuilder builder) {
        clientBuilder = Constraint.isNotNull(builder, "The HttpClientBuilder cannot be null");
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
            response = clientBuilder.buildClient().execute(get);
        } catch (Exception e) {
            log.error("{} Could not get the sector_identifier_uri contents from {}", getLogPrefix(), sectorIdUri);
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
        Type listType = new TypeToken<ArrayList<URI>>(){}.getType();
        List<URI> parsedUris = new Gson().fromJson(output, listType);
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
