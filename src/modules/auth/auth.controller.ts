import { Controller, Post, Req } from '@nestjs/common';
import { Body, Get, HttpCode, UseGuards } from '@nestjs/common/decorators';
import { RequestContext } from 'src/config/context';
import User from 'src/entities/User.entity';
import { AuthServices } from './auth.service';
import { ContextSession, GetUser } from './decorator';
import { SignInDto, SigUpDto } from './dto/auth.dto';
import { JwtGuard } from './guard';
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthServices) {}
  @Post('signUp')
  @HttpCode(201)
  signUp(@Body() dto: SigUpDto, @ContextSession() { session }: RequestContext) {
    return this.authService.signUp(dto, session);
  }
  @Post('signIn')
  @HttpCode(201)
  signIn(
    @Body() dto: SignInDto,
    @ContextSession() { session }: RequestContext,
  ) {
    return this.authService.signIn(dto, session);
  }

  @Get('refreshToken')
  @UseGuards(JwtGuard)
  refreshToken(@Req() req: RequestContext, @GetUser() user: User) {
    return this.authService.refreshToken(req, user.userID);
  }
}
