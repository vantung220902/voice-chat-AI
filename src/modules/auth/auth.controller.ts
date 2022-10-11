import { Controller, Post, Req, HttpStatus, Delete } from '@nestjs/common';
import { Body, Get, HttpCode, Put, UseGuards } from '@nestjs/common/decorators';
import { FileSystemStoredFile, FormDataRequest } from 'nestjs-form-data';
import User from 'src/modules/user/entities/User.entity';
import { ContextSession } from '../context/decorator/index.decorator';
import { RequestContext } from '../context/types';
import { AuthServices } from './auth.service';
import { GetUser } from './decorator';
import {
  ChangePasswordDto,
  ForgotPasswordDto,
  SignInDto,
  SigUpDto,
} from './dto/auth.dto';
import { JwtGuard } from './guard';
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthServices) {}
  @Post('signUp')
  @FormDataRequest({ storage: FileSystemStoredFile })
  @HttpCode(HttpStatus.CREATED)
  signUp(@Body() dto: SigUpDto) {
    return this.authService.signUp(dto);
  }
  @Post('signIn')
  @HttpCode(HttpStatus.OK)
  signIn(
    @Body() dto: SignInDto,
    @ContextSession() { session }: RequestContext,
  ) {
    return this.authService.signIn(dto, session);
  }

  @Delete('logout')
  @UseGuards(JwtGuard)
  @HttpCode(HttpStatus.OK)
  logout(@Req() req: RequestContext, @GetUser() user: User) {
    return this.authService.logout(req, user);
  }

  @Get('refreshToken')
  @UseGuards(JwtGuard)
  @HttpCode(HttpStatus.OK)
  refreshToken(@Req() req: RequestContext, @GetUser() user: User) {
    return this.authService.refreshToken(req, user.userId);
  }

  @Get('confirmCode/:code/:userID')
  @HttpCode(HttpStatus.OK)
  conformCode(@Req() req: RequestContext) {
    return this.authService.verifyCode(
      req.params?.code,
      req.params?.userID,
      req.session,
    );
  }
  @Post('forgot')
  @HttpCode(HttpStatus.OK)
  forgotPassword(
    @Body() body: ForgotPasswordDto,
    @Req() { session }: RequestContext,
  ) {
    return this.authService.forgotPassword(body, session);
  }

  @Put('change')
  @UseGuards(JwtGuard)
  @HttpCode(HttpStatus.OK)
  changePassword(@Body() body: ChangePasswordDto, @GetUser() user: User) {
    return this.authService.changePassword(body, user);
  }
}
