import { CloudinaryService } from './../cloudrary/cloudrary.service';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import * as argon2 from 'argon2';
import { randomInt } from 'crypto';
import { Model } from 'mongoose';
import { RequestContext, SessionContext } from 'src/modules/context/types';
import {
  ConfirmationCode,
  ConfirmationCodeDocument,
} from 'src/schemas/confirmationCode.schema';
import User from '../../entities/User.entity';
import {
  htmlConfirmationEmail,
  htmlForgetEmail,
  renderCode,
  sendEmail,
} from '../../utils';
import { UserService } from '../user/user.service';
import {
  ChangePasswordDto,
  ForgotPasswordDto,
  SignInDto,
  SigUpDto,
} from './dto/auth.dto';
import { IResponse, UserSecretJWT } from './types/i.base';
@Injectable({})
export class AuthServices {
  constructor(
    private readonly userService: UserService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly cloudinaryService: CloudinaryService,
    @InjectModel(ConfirmationCode.name)
    private readonly codeModel: Model<ConfirmationCodeDocument>,
  ) {}
  async createConfirmationCode(
    code: string,
    userID: string,
  ): Promise<ConfirmationCode> {
    const createdCode = new this.codeModel({
      code,
      userID,
    });
    return createdCode.save();
  }
  async verifyCode(
    code: string,
    userID: string,
    session: SessionContext,
  ): Promise<IResponse> {
    try {
      const confirmationCode = await this.codeModel.findOne({
        code,
        userID,
      });
      if (!confirmationCode)
        return {
          code: 401,
          success: false,
          message: 'Code is incorrect',
          error: [
            {
              field: 'code',
              message: 'Code is incorrect',
            },
          ],
        };
      const user = await this.userService.findUserById(confirmationCode.userID);
      if (!user) {
        throw new ForbiddenException('Credentials incorrect');
      }
      const tokenVersion = randomInt(10);
      const { accessToken, refreshToken } = await this.signToken({
        userID,
        email: user.email,
        role: user.role,
        tokenVersion,
      });
      user.tokenVersion = tokenVersion;
      await user.save();
      delete user.password;
      session.userID = user.userID;
      session.accessToken = accessToken;
      await this.codeModel.deleteOne({
        id: confirmationCode.id,
      });
      return {
        code: 200,
        success: true,
        message: 'Confirm code successfully',
        data: {
          ...user,
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
  async signUp({
    email,
    firstName,
    lastName,
    password,
    phone,
    avatar,
  }: SigUpDto): Promise<IResponse> {
    const userExists = await this.userService.findUserByEmailAndPhone(
      email,
      phone,
    );
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
    let url = null;
    let imageId = null;
    if (avatar) {
      const response = await this.cloudinaryService.uploadImage(avatar);
      if (!response.success)
        return {
          code: 401,
          success: false,
          message: response.error.message,
        };
      url = response.url;
      imageId = response.publicId;
    }
    await this.userService.insertUser(
      {
        email,
        firstName,
        lastName,
        password: hashPassword,
        phone,
      },
      url,
      imageId,
    );
    const user = await this.userService.findUserByEmail(email);
    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }

    const code = renderCode(5);
    await this.createConfirmationCode(code, user.userID);
    await sendEmail({
      html: htmlConfirmationEmail(code),
      to: email,
      subject: 'Confirmation Code',
      text: '',
    });
    delete user.password;
    return {
      code: 200,
      success: true,
      message: 'Sign Up success',
      data: {
        ...user,
      },
    };
  }
  async signIn(
    { emailOrPhone, password }: SignInDto,
    session: SessionContext,
  ): Promise<IResponse> {
    try {
      const userExists = await this.userService.findUserByEmailOrPhone(
        emailOrPhone,
      );
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

  async forgotPassword(
    { email, userID }: ForgotPasswordDto,
    session: SessionContext,
  ) {
    const user = await this.userService.findUserById(userID);
    if (!user) throw new ForbiddenException('Credentials incorrect');
    const { accessToken, refreshToken } = await this.signToken({
      userID,
      email: user.email,
      role: user.role,
      tokenVersion: user.tokenVersion,
    });
    session.userID = userID;
    session.accessToken = accessToken;
    try {
      await sendEmail({
        html: htmlForgetEmail(accessToken, refreshToken),
        to: email,
        subject: 'Your Password',
        text: '',
      });
      return {
        code: 200,
        success: true,
        message: 'Please check your email',
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
  async changePassword(body: ChangePasswordDto, user: User) {
    try {
      const { newPassword } = body;
      const hashPassword = await argon2.hash(newPassword);
      user.password = hashPassword;
      await user.save();
      return {
        code: 200,
        success: true,
        message: 'Change password successfully',
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
      const user = await this.userService.findUserById(userID);
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
  async logout(request: RequestContext, user: User): Promise<IResponse> {
    try {
      request.user = null;
      request.session.destroy((error) => {
        console.log('error', error);
      });
      user.tokenVersion += 1;
      await user.save();
      return {
        code: 200,
        success: true,
        message: 'Logout successfully',
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
