import { UpdateUserDto } from './dto/user.dto';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import User from 'src/entities/User.entity';
import { Repository } from 'typeorm';
import { SigUpDto } from '../auth/dto';
import * as argon2 from 'argon2';
import { IResponse } from '../auth/types/i.base';
import { CloudinaryService } from '../cloudrary/cloudrary.service';
@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    private readonly cloudinaryService: CloudinaryService,
  ) {}
  findUserByEmailOrPhone(emailOrPhone: string): Promise<User> {
    return this.userRepo.findOne({
      where: [{ email: emailOrPhone }, { phone: emailOrPhone }],
    });
  }
  findUserByEmailAndPhone(email: string, phone: string): Promise<User> {
    return this.userRepo.findOne({
      where: [{ email }, { phone }],
    });
  }
  findUserByEmail(email: string): Promise<User> {
    return this.userRepo.findOne({
      where: { email },
    });
  }
  findUserById(id: string): Promise<User> {
    return this.userRepo.findOne({
      where: {
        userID: id,
      },
    });
  }
  insertUser(body: SigUpDto, avatar = null, imageId = null) {
    return this.userRepo.insert({
      ...body,
      avatar,
      imageId,
    });
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
        const response = await this.cloudinaryService.uploadImage(body.avatar);
        if (!response.success)
          return {
            code: 401,
            success: false,
            message: response.error.message,
          };
        await this.cloudinaryService.removeImage(user.imageId);
        user.avatar = response.url;
      }
      await user.save();
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
