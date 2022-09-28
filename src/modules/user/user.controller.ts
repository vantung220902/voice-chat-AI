import { JwtGuard } from './../auth/guard/jwt.guard';
import { Controller, Get, UseGuards } from '@nestjs/common';
import { GetUser } from '../auth/decorator';
import User from 'src/entities/User.entity';

@UseGuards(JwtGuard)
@Controller('user')
export class UserController {
  @Get('me')
  async me(@GetUser() user: User) {
    return user;
  }
}
