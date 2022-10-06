import { Photo } from 'src/modules/user/entities/Photo.entity';
import { UserController } from './user.controller';
import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import User from 'src/modules/user/entities/User.entity';
import { CloudinaryModule } from '../cloudrary/cloudrary.module';
@Module({
  imports: [TypeOrmModule.forFeature([User, Photo]), CloudinaryModule],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
