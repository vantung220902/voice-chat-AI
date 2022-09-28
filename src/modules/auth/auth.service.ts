import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { InjectRepository } from '@nestjs/typeorm';
import * as argon2 from 'argon2';
import { randomInt } from 'crypto';
import { Model } from 'mongoose';
import { RequestContext, SessionContext } from 'src/config/context';
import {
  ConfirmationCode,
  ConfirmationCodeDocument,
} from 'src/schemas/confirmationCode.schema';
import { Repository } from 'typeorm';
import User from '../../entities/User.entity';
import { htmlConfirmationEmail, renderCode, sendEmail } from '../../utils';
import { SignInDto, SigUpDto } from './dto/auth.dto';
import { IResponse, UserSecretJWT } from './types/i.base';
@Injectable({})
export class AuthServices {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    @InjectModel(ConfirmationCode.name)
    private readonly codeModel: Model<ConfirmationCodeDocument>,
  ) {}
  async findUserByEmailOrPhone(emailOrPhone: string): Promise<User> {
    return await this.userRepo.findOne({
      where: [{ email: emailOrPhone }, { phone: emailOrPhone }],
    });
  }
  async findUserById(id: string): Promise<User> {
    return await this.userRepo.findOne({
      where: {
        userID: id,
      },
    });
  }
  async createConfirmationCode(
    code: string,
    userID: string,
  ): Promise<ConfirmationCode> {
    const createdCode = new this.codeModel({
      code,
      userID,
    });
    await createdCode.collection.createIndex(
      { createdAt: 1 },
      { expireAfterSeconds: 15 },
    );
    return createdCode.save();
  }
  async verifyCode(code: string, userID: string) {
    const confirmationCode = await this.codeModel.find({
      code,
      userID,
    });
    await this.codeModel.createIndexes({
      expireAfterSeconds: 10,
    });
    return confirmationCode;
  }
  async signUp(
    { email, firstName, lastName, password, phone }: SigUpDto,
    session: SessionContext,
  ): Promise<IResponse> {
    const userExists = await this.userRepo.findOne({
      where: [{ email }, { phone }],
    });
    if (userExists) {
      return {
        code: 401,
        success: false,
        message: 'Email or Phone is already',
        error: [
          { field: 'email', message: 'Please using another email' },
          { field: 'phone', message: 'Please using another phone' },
        ],
      };
    }
    const hashPassword = await argon2.hash(password);
    const tokenVersion = randomInt(10);
    await this.userRepo.insert({
      email,
      firstName,
      lastName,
      password: hashPassword,
      phone,
      tokenVersion,
    });

    const user = await this.userRepo.findOne({
      where: { email },
    });
    const code = renderCode(5);
    await this.createConfirmationCode(code, user.userID);
    await sendEmail({
      html: htmlConfirmationEmail(code),
      to: email,
      subject: 'Confirmation Code',
      text: '',
    });

    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }
    const { role, userID } = user;
    const { accessToken, refreshToken } = await this.signToken({
      userID,
      email: user.email,
      role,
      tokenVersion,
    });
    delete user.password;
    session.userID = user.userID;
    session.accessToken = accessToken;
    return {
      code: 200,
      success: true,
      message: 'Sign Up success',
      data: {
        ...user,
        accessToken,
        refreshToken,
      },
    };
  }
  async signIn(
    { emailOrPhone, password }: SignInDto,
    session: SessionContext,
  ): Promise<IResponse> {
    try {
      const userExists = await this.findUserByEmailOrPhone(emailOrPhone);
      if (!userExists) {
        return {
          code: 401,
          success: false,
          message: 'Incorrect information',
          error: [
            { field: 'emailOrPhone', message: 'EmailOrPhone is incorrect' },
            { field: 'password', message: 'Password  is incorrect' },
          ],
        };
      }
      const isPassword = await argon2.verify(userExists.password, password);
      if (!isPassword)
        return {
          code: 401,
          success: false,
          message: 'Incorrect information',
          error: [
            { field: 'emailOrPhone', message: 'EmailOrPhone is incorrect' },
            { field: 'password', message: 'Password  is incorrect' },
          ],
        };
      const { role, userID } = userExists;
      const tokenVersion = randomInt(10);
      const { accessToken, refreshToken } = await this.signToken({
        userID,
        email: userExists.email,
        role,
        tokenVersion,
      });
      userExists.tokenVersion = tokenVersion;
      await userExists.save();
      delete userExists.password;
      session.userID = userExists.userID;
      session.accessToken = accessToken;
      return {
        code: 200,
        success: true,
        message: 'Sign In success',
        data: {
          ...userExists,
          accessToken,
          refreshToken,
        },
      };
    } catch (error) {
      return {
        code: 401,
        success: false,
        message: 'Have somethings wrong',
        error,
      };
    }
  }
  async signToken({
    userID,
    email,
    role,
    tokenVersion,
  }: UserSecretJWT): Promise<{ accessToken: string; refreshToken: string }> {
    const data = {
      sub: userID,
      email,
      role,
      tokenVersion,
    };
    return {
      accessToken: await this.jwt.signAsync(data, {
        secret: this.config.get('JWT_SECRET'),
        expiresIn: '1h',
      }),
      refreshToken: await this.jwt.signAsync(data, {
        secret: this.config.get('JWT_SECRET_REFRESH'),
        expiresIn: '2 days',
      }),
    };
  }
  async refreshToken(
    request: RequestContext,
    userID: string,
  ): Promise<IResponse> {
    try {
      const refreshHeader = request.header('RefreshAuthorization');
      const refreshToken = refreshHeader && refreshHeader.split(' ')[1];
      const decoded = this.jwt.verify(refreshToken, {
        secret: this.config.get('JWT_SECRET_REFRESH'),
      }) as UserSecretJWT;
      const user = await this.userRepo.findOne({
        where: {
          userID,
        },
      });
      if (decoded.tokenVersion !== user.tokenVersion || !request.session.userID)
        throw new ForbiddenException('Credentials taken');
      user.tokenVersion = decoded.tokenVersion;
      await user.save();
      return {
        code: 200,
        success: true,
        message: 'Refresh Token Successfully',
        data: {
          ...(await this.signToken(decoded)),
        },
      };
    } catch (error) {
      return {
        code: 401,
        success: false,
        message: 'Have something wrong',
        error,
      };
    }
  }
}
