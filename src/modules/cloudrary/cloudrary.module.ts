import { ConfigService } from '@nestjs/config';
import { Module } from '@nestjs/common';
import { NestjsFormDataModule } from 'nestjs-form-data';
import { CloudinaryService } from './cloudrary.service';

@Module({
  imports: [NestjsFormDataModule],
  providers: [CloudinaryService, ConfigService],
  exports: [CloudinaryService, NestjsFormDataModule],
})
export class CloudinaryModule {}
