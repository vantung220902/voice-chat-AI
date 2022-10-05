import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { v2 as cloudinary } from 'cloudinary';
import { FileSystemStoredFile } from 'nestjs-form-data';
@Injectable()
export class CloudinaryService {
  constructor(private readonly config: ConfigService) {
    cloudinary.config({
      cloud_name: config.get<string>('CLOUDINARY_NAME'),
      api_key: config.get<string>('CLOUDINARY_API_KEY'),
      api_secret: config.get<string>('CLOUDINARY_API_SECRET'),
    });
  }
  uploadImage(file: FileSystemStoredFile): Promise<{
    success: boolean;
    url?: string;
    error?: Error;
    publicId?: string;
  }> {
    try {
      return new Promise((resolve) =>
        cloudinary.uploader.upload(
          file.path,
          (error: Error, res: { url: string; public_id: string }) => {
            return resolve({
              success: error ? false : true,
              url: res?.url,
              error,
              publicId: res?.public_id,
            });
          },
        ),
      );
    } catch (error) {
      return error;
    }
  }
  removeImage(publicID: string) {
    try {
      return cloudinary.uploader.destroy(publicID);
    } catch (error) {
      return error;
    }
  }
}
