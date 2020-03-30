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

package org.geant.idpextension.oidc.metadata.impl;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.RefreshableClientInformationResolver;
import org.geant.idpextension.oidc.metadata.resolver.RemoteJwkSetCache;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Based on {@link org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver}.
 */
public class DynamicFilesystemClientInformationResolver extends AbstractIdentifiableInitializableComponent implements RefreshableClientInformationResolver {

	/**
	 * Class logger.
	 */
	@Nonnull
	private final Logger log = LoggerFactory.getLogger(DynamicFilesystemClientInformationResolver.class);
	/**
	 * The cache for remote JWK key sets.
	 */
	private RemoteJwkSetCache remoteJwkSetCache;

	/**
	 * The remote key refresh interval in milliseconds. Default value: 1800000ms
	 */
	@Duration
	@Positive
	private long keyFetchInterval = 1800000;

	private final Map<String, FilesystemClientInformationResolver> map = new ConcurrentHashMap<>();

	private final Timer backgroundTaskTimer;
	private final Resource metadata;

	private File metadataDirectory;
	private DirectoryWatcher directoryWatcher;
	private DirectoryWatcherEventListener<Path> directoryWatcherEventListener;

	/**
	 * Constructor.
	 *
	 * @param metadata the metadata directory
	 * @throws IOException If the metedata cannot be loaded.
	 */
	public DynamicFilesystemClientInformationResolver(@Nonnull final Resource metadata) {
		this(null, metadata);
	}

	/**
	 * Constructor.
	 *
	 * @param metadata            the metadata file
	 * @param backgroundTaskTimer timer used to refresh metadata in the background
	 * @throws IOException If the metedata cannot be loaded.
	 */
	public DynamicFilesystemClientInformationResolver(@Nullable final Timer backgroundTaskTimer,
	                                                  @Nonnull final Resource metadata) {
		this.backgroundTaskTimer = backgroundTaskTimer;
		this.metadata = metadata;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doInitialize() throws ComponentInitializationException {
		log.info("Initializing FilesystemClientInformationDirectoryResolver for metadata directory '" + metadata + "'");
		super.doInitialize();

		File metadataDirectory;
		try {
			metadataDirectory = metadata.getFile();
		} catch (final IOException e) {
			e.printStackTrace();
			throw new ComponentInitializationException("Metadata directory configuration is invalid: " + e.getMessage());
		}

		if (!metadataDirectory.exists()) {
			throw new ComponentInitializationException("Metadata directory '" + metadataDirectory.getAbsolutePath() + "' does not exist");
		}

		if (!metadataDirectory.isDirectory()) {
			throw new ComponentInitializationException("Metadata directory '" + metadataDirectory.getAbsolutePath() + "' is not a directory");
		}

		if (!metadataDirectory.canRead()) {
			throw new ComponentInitializationException("Metadata directory '" + metadataDirectory.getAbsolutePath() + "' is not readable");
		}

		this.metadataDirectory = metadataDirectory;
		directoryWatcherEventListener = new DirectoryWatcherPathEventListener(map, remoteJwkSetCache, backgroundTaskTimer, keyFetchInterval);

		final FilenameFilter filenameFilter = new FilenameFilter() {
			@Override
			public boolean accept(File directory, String filename) {
				return filename.toLowerCase().endsWith(".json");
			}
		};

		if (metadataDirectory.listFiles() != null) {
			for (final File file : metadataDirectory.listFiles(filenameFilter)) {
				directoryWatcherEventListener.onCreate(file.toPath());
			}
		}

		try {
			directoryWatcher = new DirectoryWatcher(metadataDirectory.toPath().toAbsolutePath(), directoryWatcherEventListener);
			directoryWatcher.start();
		} catch (final IOException e) {
			log.error("Failed to register metadata directory watcher for '" + metadataDirectory.getAbsolutePath() + "': " + e.getMessage());
		}
	}

	@Override
	protected void doDestroy() {
		super.doDestroy();

		for (final FilesystemClientInformationResolver resolver : map.values()) {
			resolver.destroy();
		}

		directoryWatcher.stop();

		for (final String id : map.keySet()) {
			directoryWatcherEventListener.onDelete(Paths.get(id));
		}
	}

	/**
	 * Set the cache for remote JWK key sets.
	 *
	 * @param jwkSetCache What to set.
	 */
	public void setRemoteJwkSetCache(final RemoteJwkSetCache jwkSetCache) {
		remoteJwkSetCache = Constraint.isNotNull(jwkSetCache, "The remote JWK set cache cannot be null");
	}

	/**
	 * Set the remote key refresh interval (in milliseconds).
	 *
	 * @param interval What to set.
	 */
	public void setKeyFetchInterval(@Duration @Positive long interval) {
		if (interval < 0) {
			throw new IllegalArgumentException("Remote key refresh must be greater than 0");
		}
		keyFetchInterval = interval;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Iterable<OIDCClientInformation> resolve(CriteriaSet criteria) throws ResolverException {
		final List<OIDCClientInformation> oidcClientInformations = new LinkedList<>();
		for (final FilesystemClientInformationResolver resolver : map.values()) {
			for (OIDCClientInformation oidcClientInformation : resolver.resolve(criteria)) {
				oidcClientInformations.add(oidcClientInformation);
			}
		}

		return oidcClientInformations;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public OIDCClientInformation resolveSingle(CriteriaSet criteria) throws ResolverException {
		final Iterable<OIDCClientInformation> iterable = resolve(criteria);
		if (iterable != null) {
			final Iterator<OIDCClientInformation> iterator = iterable.iterator();
			if (iterator != null && iterator.hasNext()) {
				return iterator.next();
			}
		}

		log.warn("Could not find any clients with the given criteria");
		return null;
	}

	@Override
	public void refresh() throws ResolverException {
		for (final FilesystemClientInformationResolver resolver : map.values()) {
			resolver.refresh();
		}
	}

	@Nullable
	@Override
	public DateTime getLastRefresh() {
		DateTime ret = null;
		for (final ClientInformationResolver resolver : map.values()) {
			if (resolver instanceof RefreshableClientInformationResolver) {
				final DateTime lastUpdate = ((RefreshableClientInformationResolver) resolver).getLastUpdate();
				if (ret == null || ret.isBefore(lastUpdate)) {
					ret = lastUpdate;
				}
			}
		}

		return ret;
	}

	@Nullable
	@Override
	public DateTime getLastUpdate() {
		DateTime ret = null;
		for (final ClientInformationResolver resolver : map.values()) {
			if (resolver instanceof RefreshableClientInformationResolver) {
				final DateTime lastRefresh = ((RefreshableClientInformationResolver) resolver).getLastRefresh();
				if (ret == null || ret.isBefore(lastRefresh)) {
					ret = lastRefresh;
				}
			}
		}

		return ret;
	}
}
