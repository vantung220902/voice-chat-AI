import { UpdateUserDto } from './dto/user.dto';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import User from 'src/modules/user/entities/User.entity';
import { Repository } from 'typeorm';
import { SigUpDto } from '../auth/dto';
import * as argon2 from 'argon2';
import { IResponse } from '../auth/types/i.base';
import { CloudinaryService } from '../cloudrary/cloudrary.service';
import { Photo } from './entities/Photo.entity';
@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    @InjectRepository(Photo)
    private readonly photoRepo: Repository<Photo>,
    private readonly cloudinaryService: CloudinaryService,
  ) {}
  findUserByEmailOrPhone(emailOrPhone: string): Promise<User> {
    return this.userRepo.findOne({
      where: [{ email: emailOrPhone }, { phone: emailOrPhone }],
      relations: ['photo'],
    });
  }
  findUserByEmailAndPhone(email: string, phone: string): Promise<User> {
    return this.userRepo.findOne({
      where: [{ email }, { phone }],
      relations: ['photo'],
    });
  }
  findUserByEmail(email: string): Promise<User> {
    return this.userRepo.findOne({
      where: {
        email,
      },
    });
  }
  findUserById(id: string): Promise<User> {
    return this.userRepo.findOne({
      where: {
        userID: id,
      },
      relations: ['photo'],
    });
  }
  async insertUser(
    body: SigUpDto,
    payload: { url: string; publicId: string } | undefined,
  ) {
    let photoId = null;
    if (payload) {
      await this.photoRepo.insert({
        publicId: payload.publicId,
        url: payload.url,
      });
      const photo = await this.photoRepo.findOne({
        where: {
          publicId: payload.publicId,
        },
      });
      photoId = photo.id;
    }
    console.log('photoId', photoId);
    await this.userRepo.insert({
      ...body,
      photoId,
    });
    const user = await this.findUserByEmail(body.email);
    return user;
  }
  async updateUser(id: string, body: UpdateUserDto): Promise<IResponse> {
    try {
      const user = await this.findUserById(id);
      if (!user) throw new UnauthorizedException('userID not validate');
      user.firstName = body?.firstName ?? user.firstName;
      user.lastName = body?.lastName ?? user.lastName;
      user.phone = body?.phone ?? user.phone;
      if (body?.password && body.oldPassword) {
        const isPassword = await argon2.verify(user.password, body.oldPassword);
        if (!isPassword)
          return {
            code: 401,
            success: false,
            message: 'Incorrect information',
            error: [{ field: 'password', message: 'Password is incorrect' }],
          };
        const hashPassword = await argon2.hash(body.password);
        user.password = hashPassword;
      }
      if (body?.avatar) {
        const { success, publicId, url, error } =
          await this.cloudinaryService.uploadImage(body.avatar);
        if (!success)
          return {
            code: 401,
            success: false,
            message: error.message,
          };
        const photo = await this.photoRepo.findOne({
          where: {
            id: user.photoId,
          },
        });
        await this.cloudinaryService.removeImage(photo.publicId);
        photo.url = url;
        photo.publicId = publicId;
        await this.photoRepo.save(photo);
      }
      await this.userRepo.save(user);
      delete user.password;
      return {
        code: 200,
        success: true,
        message: 'Updated user successfully',
        data: user,
      };
    } catch (error) {
      console.log('error', error);
      return {
        code: 401,
        success: false,
        message: 'Have somethings wrong',
        error,
      };
    }
  }
}
