import * as Dockerode from 'dockerode';

import { ImageRemovalError } from './errors';

/**
 * LocalImage
 *
 * This class represents an image on a docker daemon. It also provides
 * methods to act on this image.
 */
export class LocalImage {
	/**
	 * The dockerfile which was used to build this image, if one exists
	 */
	public dockerfile?: string;

	/**
	 * Was this image built locally or imported into the docker daemon
	 * from a registry?
	 */
	public external: boolean;

	/**
	 * The reference of this image on the docker daemon. Note that this
	 * value can be null, which in a non-external image means that the
	 * base image could not be downloaed. In an image pull, the external
	 * image could not be downloaded.
	 */
	public name?: string;

	/**
	 * The service that is image is for
	 */
	public serviceName: string;

	/**
	 * The daemon which this image is stored on
	 */
	public daemon: Dockerode;

	/**
	 * The layers which make up this image build
	 */
	public layers?: string[];

	/**
	 * Was this image built successfully?
	 *
	 * Note that in the case of an image not being successfully built,
	 * this class could represent an image which is made up of all
	 * the layers that were successfully built
	 */
	public successful: boolean;

	/**
	 * If this build failed with an error, this field will contain
	 * said error.
	 */
	public error?: Error;

	public constructor(
		daemon: Dockerode,
		name: string | null,
		serviceName: string,
		external: boolean,
		successful: boolean,
	) {
		this.daemon = daemon;
		this.external = external;
		this.successful = successful;
		this.serviceName = serviceName;
		if (name != null) {
			this.name = name;
		}
	}

	/**
	 * Get a handle to the dockerode image
	 */
	public getImage(): Dockerode.Image {
		if (this.name == null) {
			throw new Error('Attempting to get image without name');
		}
		return this.daemon.getImage(this.name);
	}

	/**
	 * Delete an image from the docker daemon
	 *
	 * @throws ImageRemovalError
	 */
	public deleteImage(): Promise<void> {
		const image = this.getImage();
		return image.remove()
		.catch((e) => {
			throw new ImageRemovalError(e);
		});
	}
}