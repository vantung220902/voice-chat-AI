import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import {
  ConfirmationCode,
  ConfirmationCodeSchema,
} from 'src/schemas/confirmationCode.schema';
import { CloudinaryModule } from './../cloudrary/cloudrary.module';
import { UserModule } from './../user/user.module';
import { AuthController } from './auth.controller';
import { AuthServices } from './auth.service';
import { JwtStrategy } from './strategy';

@Module({
  imports: [
    CloudinaryModule,
    JwtModule.register({}),
    MongooseModule.forFeature([
      { name: ConfirmationCode.name, schema: ConfirmationCodeSchema },
    ]),
    UserModule,
  ],
  controllers: [AuthController],
  providers: [JwtStrategy, AuthServices, ConfigService],
})
export class AuthModule {}
