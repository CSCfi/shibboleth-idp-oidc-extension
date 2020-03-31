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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static java.nio.file.StandardWatchEventKinds.*;

/**
 * A {@link WatchService} to listen on file changes of a given directory.
 */
public class DirectoryWatcher implements Runnable {

	/**
	 * Class logger.
	 */
	private final Logger log = LoggerFactory.getLogger(DirectoryWatcher.class);

	/**
	 * Single-Threaded {@link ExecutorService} for running in the background.
	 */
	private final ExecutorService executorService = Executors.newSingleThreadExecutor();

	/**
	 * {@link Future} of the started Thread, used to stop this {@link DirectoryWatcher} on shutdown.
	 */
	private Future<?> directoryWatcherFuture;

	/**
	 * The path of the directory to watch.
	 */
	private final Path directory;

	/**
	 * The {@link WatchService}.
	 */
	private final WatchService watchService;

	/**
	 * The {@link WatchKey} of this {@link DirectoryWatcher#watchService}
	 */
	private final WatchKey key;

	/**
	 * The Event Handler for file changes.
	 */
	private final DirectoryWatcherEventHandler eventHandler;

	private final String fileExtension;

	/**
	 * {@link DirectoryWatcher#DirectoryWatcher(Path, DirectoryWatcherEventHandler, String)}
	 */
	public DirectoryWatcher(
			final Path directory,
			final DirectoryWatcherEventHandler eventHandler)
			throws IOException {
		this(directory, eventHandler, null);
	}

	/**
	 * Creates a WatchService and registers the given directory.
	 *
	 * @param directory The path of the directory to watch.
	 * @param eventHandler The Event Handler for file changes.
	 * @param fileExtension the file extension to filter for.
	 * @throws IOException on IO Errors.
	 */
	public DirectoryWatcher(
			final Path directory,
			final DirectoryWatcherEventHandler eventHandler,
			final String fileExtension)
			throws IOException {
		this.directory = directory;
		this.watchService = FileSystems.getDefault().newWatchService();
		this.key = directory.register(watchService, ENTRY_CREATE, ENTRY_MODIFY, ENTRY_DELETE);
		this.eventHandler = eventHandler;
		this.fileExtension = fileExtension;
	}

	/**
	 * Loop to take {@link WatchEvent}s and pass them to the {@link DirectoryWatcher#eventHandler}.
	 * This uses the resource-friendly {@link WatchService#take()} method which simply
	 * waits for an event instead of polling for events in a loop.
	 */
	@Override
	public void run() {
		try {
			WatchKey key;
			while ((key = watchService.take()) != null) {
				if (this.key != key) {
					log.error("Unrecognized WatchKey for directory '" + directory.toAbsolutePath().toString() + "': " + key);
					continue;
				}

				// let the WatchKey collect multiple occurrences of the same event within an extremely short time
				// which may happen while editing/deleting files, can be seen with event.count(),
				// also solves another problem (1)
				try {
					Thread.sleep(10L);
				} catch (final InterruptedException e) {
					// ignored
				}

				for (final WatchEvent<?> _event : key.pollEvents()) {
					@SuppressWarnings("unchecked")
					final WatchEvent<Path> event = (WatchEvent<Path>) _event;

					log.debug("Event occurred: Event{"
							+ "context=" + event.context() + ", "
							+ "kind=" + event.kind().name() + ", "
							+ "count=" + event.count() + "}");

					final WatchEvent.Kind<?> kind = event.kind();
					final Path path = directory.resolve(event.context());

					if (fileExtension == null || path.toString().toLowerCase().endsWith(fileExtension)) {
						if (kind == OVERFLOW) {
							continue;
						} else if (kind == ENTRY_CREATE) {
							eventHandler.onCreate(path);
						} else if (kind == ENTRY_MODIFY) {
							// (1) handle buggy events on Windows, see https://stackoverflow.com/q/28201283/11840557
							// does not resolve the problem in all situations
							// sometimes the file still "exists" and will be non-existent in the next nanosecond ...
							if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
								eventHandler.onModify(path);
							}
						} else if (kind == ENTRY_DELETE) {
							eventHandler.onDelete(path);
						} else {
							log.warn("Unrecognized event kind occurred: " + event.kind().name());
						}
					} else {
						log.debug("Skipping file: '" + path + "' (not a metadata file, extension filter: '" + fileExtension + "')");
					}
				}

				if (!key.reset()) {
					log.error("WatchKey is no longer valid, DirectoryWatcher for directory '" + directory.toAbsolutePath().toString() + "' will stop");
					break;
				}
			}
		} catch (final InterruptedException e) {
			log.warn("DirectoryWatcher for directory '" + directory.toAbsolutePath().toString() + "' threw an InterruptedException and will stop: " + e.getMessage());
		}
	}

	/**
	 * Start this {@link DirectoryWatcher} in a new Thread.
	 */
	public void start() {
		log.debug("Starting DirectoryWatcher for directory '" + directory.toAbsolutePath().toString() + "' with extension filter: '" + fileExtension + "'");
		this.directoryWatcherFuture = executorService.submit(this);
		executorService.shutdown();
		log.debug("Started DirectoryWatcher for directory '" + directory.toAbsolutePath().toString() + "'");
	}

	/**
	 * Stop this {@link DirectoryWatcher} and it's thread.
	 */
	public void stop() {
		log.debug("Stopping DirectoryWatcher for directory '" + directory.toAbsolutePath().toString() + "'");
		if (this.key != null) {
			key.cancel();
		}
		try {
			watchService.close();
		} catch (final IOException e) {
			log.warn("DirectoryWatcher for directory '" + directory.toAbsolutePath().toString() + "' threw an IOException while stopping: " + e.getMessage());
		}

		if (directoryWatcherFuture != null) {
			try {
				directoryWatcherFuture.cancel(true);
				executorService.awaitTermination(10, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
			}
			executorService.shutdownNow();
		}
		log.debug("Stopped DirectoryWatcher for directory '" + directory.toAbsolutePath().toString() + "'");
	}
}
