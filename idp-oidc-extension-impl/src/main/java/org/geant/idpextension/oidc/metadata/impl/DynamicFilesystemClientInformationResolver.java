/*
 * Copyright (c) 2020, Michael Palata
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
import net.shibboleth.utilities.java.support.component.DestructableComponent;
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
 * A metadata provider that pulls metadata files from a directory on the local filesystem, simply talking a wrapper class
 * which internally holds a collection of {@link FilesystemClientInformationResolver} which gets updated live according to file changes.
 * This is the OIDC-equivalent of Shibboleth's <a href="https://wiki.shibboleth.net/confluence/display/SP3/LocalDynamicMetadataProvider">LocalDynamicMetadataProvider</a>.
 *
 * This special implementation takes a metadata directory, loads all .json metadata files inside this directory
 * and starts a {@link WatchService} to listen on metadata file changes.
 *
 * Adding a new metadata file will add the corresponding {@link ClientInformationResolver}.
 * Updating an existing metadata file will remove the old {@link ClientInformationResolver} and add a new {@link ClientInformationResolver}.
 * Deleting a metadata file will remove the corresponding {@link ClientInformationResolver}.
 */
public class DynamicFilesystemClientInformationResolver extends AbstractIdentifiableInitializableComponent implements RefreshableClientInformationResolver {

	public static final String METADATA_FILE_EXTENSION = ".json";

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
	 * The remote key refresh interval in milliseconds. Default value: 1800000ms (30 minutes)
	 */
	@Duration
	@Positive
	private long keyFetchInterval = 1800000;

	/**
	 * The metadata resource configured by the spring bean XML.
	 */
	private final Resource metadata;


	/**
	 * Timer used to schedule background metadata update tasks.
	 */
	private final Timer backgroundTaskTimer;

	/**
	 * The internal map which holds the most recent version of the metadata files ("absolutePath" = {@link FilesystemClientInformationResolver}).
	 */
	private final Map<Path, FilesystemClientInformationResolver> map = new ConcurrentHashMap<>();

	/**
	 * The {@link DirectoryWatcher} for the {@link DynamicFilesystemClientInformationResolver#metadata} directory.
	 */
	private DirectoryWatcher directoryWatcher;

	/**
	 * The Event Handler to update the shared {@link DynamicFilesystemClientInformationResolver#map}
	 * according to metadata file changes signaled by the {@link DynamicFilesystemClientInformationResolver#directoryWatcher}.
	 */
	private DirectoryWatcherEventHandler directoryWatcherEventHandler;

	/**
	 * Default Constructor.
	 *
	 * @param metadata the metadata directory
	 */
	public DynamicFilesystemClientInformationResolver(@Nonnull final Resource metadata) {
		this(null, metadata);
	}

	/**
	 * Constructor.
	 *
	 * @param metadata            the metadata file
	 * @param backgroundTaskTimer timer used to refresh metadata in the background
	 */
	public DynamicFilesystemClientInformationResolver(@Nullable final Timer backgroundTaskTimer,
	                                                  @Nonnull final Resource metadata) {
		this.backgroundTaskTimer = backgroundTaskTimer;
		this.metadata = metadata;
	}

	/**
	 * Checks if the configured {@link DynamicFilesystemClientInformationResolver#metadata} is a valid directory,
	 * initializes all .json files as {@link FilesystemClientInformationResolver}s, adds them the shared {@link DynamicFilesystemClientInformationResolver#map}
	 * and starts the {@link DynamicFilesystemClientInformationResolver#directoryWatcher} for
	 * the given {@link DynamicFilesystemClientInformationResolver#metadata} directory.
	 */
	@Override
	protected void doInitialize() throws ComponentInitializationException {
		log.info("Initializing DynamicFilesystemClientInformationResolver for metadata directory '" + metadata + "'");
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

		directoryWatcherEventHandler = new DirectoryWatcherEventHandlerImpl(map, remoteJwkSetCache, backgroundTaskTimer, keyFetchInterval);

		final FilenameFilter filenameFilter = new FilenameFilter() {
			@Override
			public boolean accept(File directory, String filename) {
				return filename.toLowerCase().endsWith(METADATA_FILE_EXTENSION);
			}
		};

		final File[] metadataFiles = metadataDirectory.listFiles(filenameFilter);
		if (metadataFiles != null) {
			for (final File file : metadataFiles) {
				directoryWatcherEventHandler.onCreate(file.toPath().toAbsolutePath());
			}
		}

		try {
			directoryWatcher = new DirectoryWatcher(
					metadataDirectory.toPath().toAbsolutePath(),
					directoryWatcherEventHandler,
					METADATA_FILE_EXTENSION);
			directoryWatcher.start();
		} catch (final IOException e) {
			log.error("Failed to register metadata directory watcher for '" + metadataDirectory.getAbsolutePath() + "': " + e.getMessage());
		}
	}

	/**
	 * Calls the {@link DestructableComponent#destroy()} method an all {@link FilesystemClientInformationResolver}s
	 * in the shared {@link DynamicFilesystemClientInformationResolver#map} and removes them from the map.
	 */
	@Override
	protected void doDestroy() {
		super.doDestroy();

		directoryWatcher.stop();

		for (final Path path : map.keySet()) {
			directoryWatcherEventHandler.onDelete(path);
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
	 *
	 * Propagates the {@link #resolve(CriteriaSet)} call to all {@link FilesystemClientInformationResolver}s in the
	 * shared {@link DynamicFilesystemClientInformationResolver#map}.
	 *
	 * @param criteria the resolve criteria.
	 * @return a collection of all results from the {@link DynamicFilesystemClientInformationResolver#map}.
	 * @throws ResolverException on Errors.
	 */
	@Override
	@Nonnull
	public Iterable<OIDCClientInformation> resolve(final CriteriaSet criteria) throws ResolverException {
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
	 *
	 * @param criteria the resolve criteria.
	 * @return the first match for the criteria in the {@link DynamicFilesystemClientInformationResolver#map} or null if no match was found.
	 * @throws ResolverException on Errors.
	 */
	@Override
	@Nullable
	public OIDCClientInformation resolveSingle(final CriteriaSet criteria) throws ResolverException {
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

	/**
	 * Propagates the {@link #refresh()} call to all {@link FilesystemClientInformationResolver}s in the
	 * shared {@link DynamicFilesystemClientInformationResolver#map}.
	 *
	 * @throws ResolverException on Errors.
	 */
	@Override
	public void refresh() throws ResolverException {
		for (final FilesystemClientInformationResolver resolver : map.values()) {
			resolver.refresh();
		}
	}

	/**
	 * Propagates the {@link #getLastRefresh()} call to all {@link FilesystemClientInformationResolver}s in the
	 * shared {@link DynamicFilesystemClientInformationResolver#map}.
	 *
	 * @return the last refresh time found in the whole {@link DynamicFilesystemClientInformationResolver#map}.
	 */
	@Override
	@Nullable
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

	/**
	 * Propagates the {@link #getLastUpdate()} call to all {@link FilesystemClientInformationResolver}s in the
	 * shared {@link DynamicFilesystemClientInformationResolver#map}.
	 *
	 * @return the last update time found in the whole {@link DynamicFilesystemClientInformationResolver#map}.
	 */
	@Override
	@Nullable
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
