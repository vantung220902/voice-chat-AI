import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { TypeOrmModule } from '@nestjs/typeorm';
import {
  ConfirmationCode,
  ConfirmationCodeSchema,
} from 'src/schemas/confirmationCode.schema';
import User from '../../entities/User.entity';
import { AuthController } from './auth.controller';
import { AuthServices } from './auth.service';
import { JwtStrategy } from './strategy';

@Module({
  imports: [
    JwtModule.register({}),
    TypeOrmModule.forFeature([User]),
    MongooseModule.forFeature([
      { name: ConfirmationCode.name, schema: ConfirmationCodeSchema },
    ]),
  ],
  controllers: [AuthController],
  providers: [JwtStrategy, AuthServices, ConfigService],
})
export class AuthModule {}
