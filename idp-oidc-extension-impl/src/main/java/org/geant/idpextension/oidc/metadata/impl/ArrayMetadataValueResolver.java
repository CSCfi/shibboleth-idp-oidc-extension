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

package org.geant.idpextension.oidc.metadata.impl;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.geant.idpextension.oidc.metadata.resolver.MetadataValueResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * An implementation to {@link MetadataValueResolver} that contains an array of other {@link MetadataValueResolver}s
 * 
 */
public class ArrayMetadataValueResolver extends AbstractIdentifiableInitializableComponent
    implements MetadataValueResolver {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ArrayMetadataValueResolver.class);
    
    /** The name of the JSON object, can be null to return only values of embedded resolvers. */
    private String objectName;
    
    /** The list of resolvers whose value is added to the result of this resolver. */
    private List<MetadataValueResolver> embeddedResolvers;
    
    /** Constructor. */
    public ArrayMetadataValueResolver() {
        objectName = null;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (embeddedResolvers == null) {
            throw new ComponentInitializationException("The list of embedded resolvers cannot be null");
        }
    }
    
    /**
     * Set the list of resolvers whose value is added to the result of this resolver.
     * @param resolvers What to set.
     */
    public void setEmbeddedResolvers(final List<MetadataValueResolver> resolvers) {
        embeddedResolvers = Constraint.isNotNull(resolvers, "The list of embedded resolvers cannot be null");
    }
    
    /**
     * Set the name of the JSON object, can be null to return only values of embedded resolvers.
     * @param name What to set.
     */
    public void setObjectName(final String name) {
        objectName = StringSupport.trimOrNull(name);
    }

    /** {@inheritDoc} */
    @Override
    public Iterable<Object> resolve(CriteriaSet criteria) throws ResolverException {
        if (criteria != null && !criteria.isEmpty()) {
            log.warn("All the criteria are currently ignored");
        }
        final List<Object> result = new ArrayList<>();
        for (final MetadataValueResolver resolver : embeddedResolvers) {
            log.debug("Adding the result from the resolver {}", resolver.getId());
            result.add(resolver.resolveSingle(criteria));
        }
        return result;
    }

    /** {@inheritDoc} */
    @Override
    public Object resolveSingle(CriteriaSet criteria) throws ResolverException {
        final JSONArray jsonArray = new JSONArray();
        final Iterator<Object> iterator = resolve(criteria).iterator();
        while (iterator.hasNext()) {
            jsonArray.add(iterator.next());
        }
        if (objectName == null) {
            return jsonArray;            
        } else {
            final JSONObject jsonObject = new JSONObject();
            jsonObject.put(objectName, jsonArray);
            return jsonObject;
        }
    }
}